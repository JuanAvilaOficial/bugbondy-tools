"""Módulo de límites de velocidad y control de peticiones.

Protege al pipeline contra picos de tráfico, abuso o ejecuciones descontroladas
de herramientas externas. Implementa:
1. Herencia de límites (global -> programa -> herramienta).
2. Algoritmo Token Bucket con refil continuo.
3. Presupuesto diario por programa.
4. Control de concurrencia mediante slots.
5. Persistencia cross-proceso mediante SQLite (WAL mode y transacciones ACID).
"""

from __future__ import annotations

import sqlite3
import threading
import time
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

import yaml
from pydantic import BaseModel, ConfigDict, Field

DEFAULT_RATE_LIMITS_PATH = "config/rate-limits.yaml"
DEFAULT_RATE_LIMIT_DB_PATH = "state/pipeline.db"


class RateLimitExceededError(Exception):
    """Lanzada cuando se excede el límite de velocidad de una petición."""

    def __init__(self, retry_after: float, limit: float, scope_key: str) -> None:
        self.retry_after = retry_after
        self.limit = limit
        self.scope_key = scope_key
        super().__init__(
            f"Límite de velocidad excedido para '{scope_key}' (límite: {limit} req/s). "
            f"Reintento en {retry_after:.2f}s."
        )


@dataclass(frozen=True)
class RateLimitDecision:
    allowed: bool
    scope_key: str
    limit: float
    remaining: float
    retry_after: float
    cooldown_seconds: float


@dataclass(frozen=True)
class EffectiveLimits:
    max_requests_per_second: float
    concurrency: int
    cooldown_seconds_on_429: float
    daily_request_budget: int | None


class ToolRateLimit(BaseModel):
    rate_limit: float | None = None
    concurrency: int | None = None
    bulk_size: int | None = None
    max_rate: float | None = None
    timing_template: str | None = None


class ProgramRateLimit(BaseModel):
    max_requests_per_second: float = 15.0
    concurrency: int = 5
    daily_request_budget: int | None = None


class GlobalRateLimit(BaseModel):
    max_requests_per_second: float = 15.0
    default_concurrency: int = 5
    cooldown_seconds_on_429: float = 60.0
    user_agent: str | None = None


class RateLimitsConfig(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    version: str = "1.0"
    global_limits: GlobalRateLimit = Field(default_factory=GlobalRateLimit, alias="global")
    programs: dict[str, ProgramRateLimit] = Field(default_factory=dict)
    tools: dict[str, ToolRateLimit] = Field(default_factory=dict)


class TokenBucket:
    """Bucket de tokens en memoria con refil continuo."""

    def __init__(self, capacity: float, refill_rate: float) -> None:
        self.capacity = max(0.0, capacity)
        self.refill_rate = max(0.0, refill_rate)
        self.tokens = self.capacity
        self.last_refill = time.monotonic()

    def _refill(self, now: float) -> None:
        if self.refill_rate > 0 and now > self.last_refill:
            self.tokens = min(self.capacity, self.tokens + (now - self.last_refill) * self.refill_rate)
        self.last_refill = now

    def try_consume(self, now: float | None = None, tokens: float = 1.0) -> bool:
        """Intenta consumir tokens; con refil continuo permite bursts hasta el capacity."""
        current = time.monotonic() if now is None else now
        self._refill(current)
        if self.tokens + 1e-9 >= tokens:
            self.tokens -= tokens
            return True
        return False

    def retry_after(self, now: float | None = None, tokens: float = 1.0) -> float:
        """Segundos hasta que un token esté disponible para el siguiente request."""
        current = time.monotonic() if now is None else now
        self._refill(current)
        if self.tokens >= tokens:
            return 0.0
        if self.refill_rate <= 0:
            return float("inf")
        return max(0.0, (tokens - self.tokens) / self.refill_rate)


class SQLiteRateLimitStorage:
    """Almacén SQLite persistente cross-proceso para límites de velocidad."""

    def __init__(self, db_path: str | Path) -> None:
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=30.0, autocommit=True)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode = WAL;")
        conn.execute("PRAGMA busy_timeout = 10000;")
        return conn

    def _init_db(self) -> None:
        conn = self._get_connection()
        try:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS rate_limit_buckets (
                    scope_key TEXT PRIMARY KEY,
                    tokens REAL NOT NULL,
                    capacity REAL NOT NULL,
                    refill_rate REAL NOT NULL,
                    last_refill REAL NOT NULL,
                    daily_date TEXT NOT NULL,
                    daily_count INTEGER NOT NULL,
                    cooldown_until REAL NOT NULL DEFAULT 0.0,
                    active_concurrency INTEGER NOT NULL DEFAULT 0,
                    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
                )
                """
            )
        finally:
            conn.close()

    def consume(
        self,
        scope_key: str,
        limits: EffectiveLimits,
        now_val: float,
        tokens_to_consume: float = 1.0,
    ) -> RateLimitDecision:
        today = datetime.fromtimestamp(now_val, tz=UTC).date().isoformat()
        capacity = max(0.0, limits.max_requests_per_second)
        refill_rate = capacity

        if capacity <= 0.0:
            return RateLimitDecision(
                allowed=False,
                scope_key=scope_key,
                limit=0.0,
                remaining=0.0,
                retry_after=limits.cooldown_seconds_on_429,
                cooldown_seconds=limits.cooldown_seconds_on_429,
            )

        conn = self._get_connection()
        try:
            conn.execute("BEGIN IMMEDIATE")
            row = conn.execute(
                "SELECT * FROM rate_limit_buckets WHERE scope_key = ?",
                (scope_key,),
            ).fetchone()

            if row is None:
                current_tokens = capacity
                last_refill = now_val
                daily_date = today
                daily_count = 0
                cooldown_until = 0.0
                active_concurrency = 0
            else:
                last_refill = float(row["last_refill"])
                current_tokens = float(row["tokens"])
                daily_date = row["daily_date"]
                daily_count = int(row["daily_count"])
                cooldown_until = float(row["cooldown_until"])
                active_concurrency = int(row["active_concurrency"])

            # 1. Resetear contador diario si cambió la fecha
            if daily_date != today:
                daily_date = today
                daily_count = 0

            # 2. Refil continuo
            if now_val > last_refill and refill_rate > 0:
                current_tokens = min(capacity, current_tokens + (now_val - last_refill) * refill_rate)
            last_refill = now_val

            # 3. Comprobar cooldown
            if now_val < cooldown_until:
                conn.execute("COMMIT")
                return RateLimitDecision(
                    allowed=False,
                    scope_key=scope_key,
                    limit=capacity,
                    remaining=current_tokens,
                    retry_after=cooldown_until - now_val,
                    cooldown_seconds=limits.cooldown_seconds_on_429,
                )

            # 4. Comprobar presupuesto diario
            if limits.daily_request_budget is not None and daily_count >= limits.daily_request_budget:
                conn.execute("COMMIT")
                return RateLimitDecision(
                    allowed=False,
                    scope_key=scope_key,
                    limit=capacity,
                    remaining=0.0,
                    retry_after=limits.cooldown_seconds_on_429,
                    cooldown_seconds=limits.cooldown_seconds_on_429,
                )

            # 5. Intentar consumir token
            if current_tokens + 1e-9 >= tokens_to_consume:
                current_tokens -= tokens_to_consume
                daily_count += 1
                allowed = True
                retry_after = 0.0
            else:
                allowed = False
                retry_after = (
                    (tokens_to_consume - current_tokens) / refill_rate if refill_rate > 0 else float("inf")
                )

            conn.execute(
                """
                INSERT INTO rate_limit_buckets (
                    scope_key, tokens, capacity, refill_rate, last_refill,
                    daily_date, daily_count, cooldown_until, active_concurrency, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))
                ON CONFLICT(scope_key) DO UPDATE SET
                    tokens = excluded.tokens,
                    capacity = excluded.capacity,
                    refill_rate = excluded.refill_rate,
                    last_refill = excluded.last_refill,
                    daily_date = excluded.daily_date,
                    daily_count = excluded.daily_count,
                    cooldown_until = excluded.cooldown_until,
                    active_concurrency = excluded.active_concurrency,
                    updated_at = datetime('now')
                """,
                (
                    scope_key,
                    current_tokens,
                    capacity,
                    refill_rate,
                    last_refill,
                    daily_date,
                    daily_count,
                    cooldown_until,
                    active_concurrency,
                ),
            )
            conn.execute("COMMIT")

            return RateLimitDecision(
                allowed=allowed,
                scope_key=scope_key,
                limit=capacity,
                remaining=current_tokens if allowed else 0.0,
                retry_after=retry_after,
                cooldown_seconds=limits.cooldown_seconds_on_429,
            )
        finally:
            conn.close()

    def acquire_concurrency(self, scope_key: str, max_concurrency: int) -> bool:
        if max_concurrency <= 0:
            return False

        conn = self._get_connection()
        try:
            conn.execute("BEGIN IMMEDIATE")
            row = conn.execute(
                "SELECT active_concurrency FROM rate_limit_buckets WHERE scope_key = ?",
                (scope_key,),
            ).fetchone()
            current = int(row["active_concurrency"]) if row else 0

            if current < max_concurrency:
                new_val = current + 1
                conn.execute(
                    """
                    INSERT INTO rate_limit_buckets (scope_key, tokens, capacity, refill_rate, last_refill, daily_date, daily_count, active_concurrency)
                    VALUES (?, 1.0, 1.0, 1.0, 0.0, '', 0, ?)
                    ON CONFLICT(scope_key) DO UPDATE SET active_concurrency = ?
                    """,
                    (scope_key, new_val, new_val),
                )
                conn.execute("COMMIT")
                return True
            conn.execute("COMMIT")
            return False
        finally:
            conn.close()

    def release_concurrency(self, scope_key: str) -> None:
        conn = self._get_connection()
        try:
            conn.execute("BEGIN IMMEDIATE")
            row = conn.execute(
                "SELECT active_concurrency FROM rate_limit_buckets WHERE scope_key = ?",
                (scope_key,),
            ).fetchone()
            if row:
                new_val = max(0, int(row["active_concurrency"]) - 1)
                conn.execute(
                    "UPDATE rate_limit_buckets SET active_concurrency = ? WHERE scope_key = ?",
                    (new_val, scope_key),
                )
            conn.execute("COMMIT")
        finally:
            conn.close()


class RateLimiter:
    """Control de peticiones con límites de velocidad configurables y persistencia cross-proceso."""

    def __init__(
        self,
        config_path: str | Path | None = None,
        config: RateLimitsConfig | None = None,
        storage_path: str | Path | None = None,
    ) -> None:
        self.config = config if config is not None else self.load_config(config_path)
        self.storage_path = Path(storage_path) if storage_path is not None else None
        self._storage = SQLiteRateLimitStorage(self.storage_path) if self.storage_path else None
        self._buckets: dict[str, TokenBucket] = {}
        self._active: dict[str, int] = {}
        self._daily_usage: dict[str, tuple[str, int]] = {}
        self._lock = threading.RLock()

    @classmethod
    def load_config(cls, path: str | Path | None = None) -> RateLimitsConfig:
        resolved = Path(path) if path is not None else Path(DEFAULT_RATE_LIMITS_PATH)
        if not resolved.exists():
            return RateLimitsConfig()
        with open(resolved, "r", encoding="utf-8") as f:
            raw = yaml.safe_load(f)
        return RateLimitsConfig.model_validate(raw or {})

    def _effective_limits(self, program_id: str | None, tool: str | None) -> EffectiveLimits:
        global_limits = self.config.global_limits
        limits = EffectiveLimits(
            max_requests_per_second=global_limits.max_requests_per_second,
            concurrency=global_limits.default_concurrency,
            cooldown_seconds_on_429=global_limits.cooldown_seconds_on_429,
            daily_request_budget=None,
        )

        if program_id is not None and program_id in self.config.programs:
            program = self.config.programs[program_id]
            limits = EffectiveLimits(
                max_requests_per_second=program.max_requests_per_second,
                concurrency=program.concurrency,
                cooldown_seconds_on_429=global_limits.cooldown_seconds_on_429,
                daily_request_budget=program.daily_request_budget,
            )

        if tool is not None:
            tool_conf = self.config.tools.get(tool.lower())
            if tool_conf is not None:
                limits = EffectiveLimits(
                    max_requests_per_second=(
                        tool_conf.rate_limit
                        if tool_conf.rate_limit is not None
                        else limits.max_requests_per_second
                    ),
                    concurrency=(
                        tool_conf.concurrency
                        if tool_conf.concurrency is not None
                        else limits.concurrency
                    ),
                    cooldown_seconds_on_429=limits.cooldown_seconds_on_429,
                    daily_request_budget=limits.daily_request_budget,
                )

        return limits

    def _daily_key(self, program_id: str, now_val: float) -> tuple[str, int]:
        day = datetime.fromtimestamp(now_val, tz=UTC).date().isoformat()
        stored = self._daily_usage.get(program_id)
        if stored is None or stored[0] != day:
            stored = (day, 0)
            self._daily_usage[program_id] = stored
        return stored

    def consume(
        self,
        program_id: str | None = None,
        tool: str | None = None,
        *,
        now: float | None = None,
    ) -> RateLimitDecision:
        """Evalúa y consume un slot del presupuesto de velocidad."""
        limits = self._effective_limits(program_id, tool)
        scope_key = f"{program_id or 'global'}::{tool or 'default'}"
        now_val = time.time() if now is None else now

        # Si tenemos almacenamiento persistente SQLite, usarlo para sincronizar cross-proceso
        if self._storage is not None:
            return self._storage.consume(scope_key, limits, now_val)

        # Fallback en memoria (para unit tests locales)
        allowed = limits.max_requests_per_second > 0
        retry_after = limits.cooldown_seconds_on_429 if not allowed else 0.0
        remaining = limits.max_requests_per_second if allowed else 0.0

        if allowed:
            bucket = self._buckets.setdefault(
                scope_key,
                TokenBucket(limits.max_requests_per_second, limits.max_requests_per_second),
            )
            allowed = bucket.try_consume(now=now_val)
            retry_after = bucket.retry_after(now=now_val)
            remaining = bucket.tokens

        decision = RateLimitDecision(
            allowed=allowed,
            scope_key=scope_key,
            limit=limits.max_requests_per_second,
            remaining=remaining,
            retry_after=retry_after,
            cooldown_seconds=limits.cooldown_seconds_on_429,
        )

        with self._lock:
            if allowed and limits.daily_request_budget is not None and program_id is not None:
                day_key, count = self._daily_key(program_id, now_val)
                if count >= limits.daily_request_budget:
                    allowed = False
                    retry_after = max(retry_after, limits.cooldown_seconds_on_429)

            if allowed and limits.daily_request_budget is not None and program_id is not None:
                day_key, count = self._daily_key(program_id, now_val)
                self._daily_usage[program_id] = (day_key, count + 1)

            if not allowed:
                decision = RateLimitDecision(
                    allowed=False,
                    scope_key=decision.scope_key,
                    limit=decision.limit,
                    remaining=0.0,
                    retry_after=retry_after,
                    cooldown_seconds=decision.cooldown_seconds,
                )

        return decision

    def enforce(
        self,
        program_id: str | None = None,
        tool: str | None = None,
        *,
        now: float | None = None,
    ) -> RateLimitDecision:
        """Consome un slot y lanza RateLimitExceededError si el límite fue violado."""
        decision = self.consume(program_id=program_id, tool=tool, now=now)
        if not decision.allowed:
            raise RateLimitExceededError(
                retry_after=decision.retry_after,
                limit=decision.limit,
                scope_key=decision.scope_key,
            )
        return decision

    @contextmanager
    def throttle(
        self,
        program_id: str | None = None,
        tool: str | None = None,
        *,
        now: float | None = None,
    ) -> Iterator[RateLimitDecision]:
        """Controla concurrencia: solo permite hasta `limits.concurrency` slots activos."""
        limits = self._effective_limits(program_id, tool)
        scope_key = f"{program_id or 'global'}::{tool or 'default'}"
        decision = self.consume(program_id=program_id, tool=tool, now=now)
        acquired = False

        if self._storage is not None:
            if decision.allowed and limits.concurrency > 0:
                acquired = self._storage.acquire_concurrency(scope_key, limits.concurrency)
                if not acquired:
                    decision = RateLimitDecision(
                        allowed=False,
                        scope_key=decision.scope_key,
                        limit=decision.limit,
                        remaining=decision.remaining,
                        retry_after=max(decision.retry_after, decision.cooldown_seconds),
                        cooldown_seconds=decision.cooldown_seconds,
                    )
            try:
                yield decision
            finally:
                if acquired:
                    self._storage.release_concurrency(scope_key)
            return

        # Modo en memoria
        with self._lock:
            if decision.allowed and limits.concurrency > 0:
                if self._active.get(scope_key, 0) < limits.concurrency:
                    self._active[scope_key] = self._active.get(scope_key, 0) + 1
                    acquired = True
                else:
                    decision = RateLimitDecision(
                        allowed=False,
                        scope_key=decision.scope_key,
                        limit=decision.limit,
                        remaining=decision.remaining,
                        retry_after=max(decision.retry_after, decision.cooldown_seconds),
                        cooldown_seconds=decision.cooldown_seconds,
                    )

        try:
            yield decision
        finally:
            if acquired:
                with self._lock:
                    self._active[scope_key] = max(0, self._active.get(scope_key, 0) - 1)


# Limiter por defecto: persiste en SQLite si existe state/pipeline.db
_default_storage = DEFAULT_RATE_LIMIT_DB_PATH if Path(DEFAULT_RATE_LIMIT_DB_PATH).parent.exists() else None
_DEFAULT_RATE_LIMITER = RateLimiter(storage_path=_default_storage)


def check_rate_limit(
    program_id: str | None = None,
    tool: str | None = None,
    enforce: bool = True,
    storage_path: str | Path | None = None,
) -> RateLimitDecision:
    """API reutilizable para skills: evalúa un request contra los límites vigentes.

    Lanza RateLimitExceededError si enforce=True y el límite fue superado.
    """
    limiter = RateLimiter(storage_path=storage_path) if storage_path is not None else _DEFAULT_RATE_LIMITER
    if enforce:
        return limiter.enforce(program_id=program_id, tool=tool)
    return limiter.consume(program_id=program_id, tool=tool)
