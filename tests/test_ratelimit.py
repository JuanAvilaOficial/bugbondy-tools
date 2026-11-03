import pytest

from bbpipeline.ratelimit import (
    ProgramRateLimit,
    RateLimiter,
    RateLimitExceededError,
    RateLimitsConfig,
    ToolRateLimit,
)


@pytest.fixture
def default_limiter() -> RateLimiter:
    return RateLimiter(config=RateLimitsConfig())


def test_allows_requests_under_global_default(default_limiter: RateLimiter):
    decisions = [default_limiter.consume() for _ in range(3)]

    assert all(d.allowed for d in decisions)
    # Capacidad inicial del bucket global (15 req/s) -> primer request consume 1 token
    assert decisions[0].remaining == pytest.approx(14.0)
    assert decisions[0].limit == pytest.approx(15.0)


def test_denies_request_when_rate_limit_exceeded(default_limiter: RateLimiter):
    decisions = [default_limiter.consume() for _ in range(16)]

    assert decisions[14].allowed is True  # El último dentro del límite (15)
    denied = decisions[15]
    assert denied.allowed is False
    assert denied.limit == pytest.approx(15.0)
    assert denied.retry_after > 0


def test_rate_limit_exceeded_raises_in_enforce(default_limiter: RateLimiter):
    for _ in range(20):
        default_limiter.consume()

    with pytest.raises(RateLimitExceededError):
        default_limiter.enforce()


def test_token_bucket_refills_over_time():
    limiter = RateLimiter(
        config=RateLimitsConfig(
            programs={"prog-a": ProgramRateLimit(max_requests_per_second=2, concurrency=5)},
        )
    )
    now = 1_000_000.0

    assert limiter.consume(program_id="prog-a", now=now).allowed is True
    assert limiter.consume(program_id="prog-a", now=now).allowed is True
    denied = limiter.consume(program_id="prog-a", now=now)
    assert denied.allowed is False
    assert denied.retry_after == pytest.approx(0.5)  # (1 token faltante) / (2 tokens/s)

    # Tras esperar 1 segundo, el refil habilita un nuevo request
    assert limiter.consume(program_id="prog-a", now=now + 1.0).allowed is True


def test_tool_override_limits():
    limiter = RateLimiter(
        config=RateLimitsConfig(
            tools={
                "nuclei": ToolRateLimit(rate_limit=2, concurrency=5, bulk_size=5),
            },
        )
    )

    assert limiter.consume(program_id="example-program", tool="nuclei").allowed is True
    assert limiter.consume(program_id="example-program", tool="nuclei").allowed is True
    assert limiter.consume(program_id="example-program", tool="nuclei").allowed is False

    # Otras herramientas sin override usan el límite global
    assert limiter.consume(program_id="example-program", tool="ffuf").allowed is True


def test_program_override_limits():
    limiter = RateLimiter(
        config=RateLimitsConfig(
            programs={
                "prog-b": ProgramRateLimit(max_requests_per_second=1, concurrency=3),
            },
        )
    )

    assert limiter.consume(program_id="prog-b").allowed is True
    assert limiter.consume(program_id="prog-b").allowed is False


def test_daily_request_budget_exceeded():
    limiter = RateLimiter(
        config=RateLimitsConfig(
            programs={
                "prog-c": ProgramRateLimit(max_requests_per_second=100, daily_request_budget=2),
            },
        )
    )

    assert limiter.consume(program_id="prog-c").allowed is True
    assert limiter.consume(program_id="prog-c").allowed is True
    denied = limiter.consume(program_id="prog-c")
    assert denied.allowed is False
    assert denied.retry_after > 0


def test_zero_rate_fails_closed():
    limiter = RateLimiter(
        config=RateLimitsConfig(
            programs={
                "prog-d": ProgramRateLimit(max_requests_per_second=0, concurrency=1),
            },
        )
    )

    decision = limiter.consume(program_id="prog-d")
    assert decision.allowed is False
    assert decision.retry_after > 0


def test_cooldown_seconds_on_429(default_limiter: RateLimiter):
    # Explotar el bucket (15 req/s) hasta obtener un rechazo
    denied = None
    for _ in range(20):
        denied = default_limiter.consume()
    assert denied is not None
    assert denied.allowed is False
    assert denied.cooldown_seconds == 60.0
    assert denied.retry_after > 0


def test_concurrency_limit_with_throttle():
    limiter = RateLimiter(
        config=RateLimitsConfig(
            programs={
                "prog-e": ProgramRateLimit(max_requests_per_second=10, concurrency=1),
            },
        )
    )

    with limiter.throttle(program_id="prog-e") as first:
        assert first.allowed is True
        with limiter.throttle(program_id="prog-e") as second:
            assert second.allowed is False  # Slot de concurrencia ocupado

    with limiter.throttle(program_id="prog-e") as third:
        assert third.allowed is True


def test_load_config_from_yaml_file(tmp_path):
    config_file = tmp_path / "rate-limits.yaml"
    config_file.write_text(
        """
version: "1.0"
global:
  max_requests_per_second: 1
  default_concurrency: 2
  cooldown_seconds_on_429: 30
programs:
  prog-f:
    max_requests_per_second: 1
    concurrency: 2
    daily_request_budget: 10
""",
        encoding="utf-8",
    )

    limiter = RateLimiter(config_path=config_file)

    assert limiter.consume().allowed is True
    assert limiter.consume().allowed is False


def test_sqlite_persistence_across_multiple_instances(tmp_path):
    db_file = tmp_path / "cross_process_ratelimit.db"
    cfg = RateLimitsConfig(
        programs={"shared-prog": ProgramRateLimit(max_requests_per_second=2, concurrency=5)},
    )
    now = 2_000_000.0

    # Proceso 1 (instancia A)
    proc1 = RateLimiter(config=cfg, storage_path=db_file)
    assert proc1.consume(program_id="shared-prog", now=now).allowed is True
    assert proc1.consume(program_id="shared-prog", now=now).allowed is True

    # Proceso 2 (instancia B, nuevo proceso leyendo la misma BD)
    proc2 = RateLimiter(config=cfg, storage_path=db_file)
    denied = proc2.consume(program_id="shared-prog", now=now)
    assert denied.allowed is False
    assert denied.remaining == 0.0

    # Esperar 1 segundo: Proceso 2 debe poder consumir gracias al refill persistido
    assert proc2.consume(program_id="shared-prog", now=now + 1.0).allowed is True


def test_sqlite_daily_budget_persists_across_instances(tmp_path):
    db_file = tmp_path / "cross_process_budget.db"
    cfg = RateLimitsConfig(
        programs={"budget-prog": ProgramRateLimit(max_requests_per_second=100, daily_request_budget=2)},
    )
    now = 2_000_000.0

    proc_a = RateLimiter(config=cfg, storage_path=db_file)
    proc_b = RateLimiter(config=cfg, storage_path=db_file)

    assert proc_a.consume(program_id="budget-prog", now=now).allowed is True
    assert proc_b.consume(program_id="budget-prog", now=now).allowed is True

    # El presupuesto diario es 2: ambas instancias deben ver el presupuesto agotado
    assert proc_a.consume(program_id="budget-prog", now=now).allowed is False
    assert proc_b.consume(program_id="budget-prog", now=now).allowed is False


def test_sqlite_concurrency_throttle_across_instances(tmp_path):
    db_file = tmp_path / "cross_process_throttle.db"
    cfg = RateLimitsConfig(
        programs={"concurrent-prog": ProgramRateLimit(max_requests_per_second=100, concurrency=1)},
    )
    now = 2_000_000.0

    worker1 = RateLimiter(config=cfg, storage_path=db_file)
    worker2 = RateLimiter(config=cfg, storage_path=db_file)

    with worker1.throttle(program_id="concurrent-prog", now=now) as slot1:
        assert slot1.allowed is True
        # worker2 intenta adquirir slot mientras worker1 lo tiene ocupado
        with worker2.throttle(program_id="concurrent-prog", now=now) as slot2:
            assert slot2.allowed is False

    # Una vez liberado por worker1, worker2 puede adquirirlo
    with worker2.throttle(program_id="concurrent-prog", now=now) as slot3:
        assert slot3.allowed is True
