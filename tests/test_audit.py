import json

from bbpipeline.audit import GENESIS_HASH, AuditLogger, verify_audit_file


def test_audit_hash_chaining(tmp_path):
    log_file = tmp_path / "test_audit.jsonl"
    logger = AuditLogger(log_file)

    # Evento 1
    e1 = logger.log(stage="00-scope-manager", event="target_checked", target="test.example.com", actor="agent")
    assert e1["prev_hash"] == GENESIS_HASH
    assert len(e1["hash"]) == 64

    # Evento 2
    e2 = logger.log(stage="01-recon", event="asset_discovered", target="api.example.com", actor="agent")
    assert e2["prev_hash"] == e1["hash"]

    # Evento 3
    e3 = logger.log(stage="05-verify", event="human_verified", target="finding:1", actor="human:alice")
    assert e3["prev_hash"] == e2["hash"]

    # Verificar integridad de la cadena
    is_valid, count, error = verify_audit_file(log_file)
    assert is_valid is True
    assert count == 3
    assert error is None


def test_audit_tamper_detection_line_modified(tmp_path):
    log_file = tmp_path / "tamper_test.jsonl"
    logger = AuditLogger(log_file)

    logger.log(stage="01-recon", event="scan_started", target="test.example.com")
    logger.log(stage="01-recon", event="subdomain_found", target="sub.example.com")
    logger.log(stage="02-fingerprint", event="tech_detected", target="sub.example.com")

    # Modificar una línea existente simulando ataque o corrupción
    lines = log_file.read_text(encoding="utf-8").splitlines()
    entry = json.loads(lines[1])
    entry["target"] = "tampered.target.com"  # cambio malicioso sin actualizar hash
    lines[1] = json.dumps(entry)
    log_file.write_text("\n".join(lines) + "\n", encoding="utf-8")

    is_valid, bad_line, error = verify_audit_file(log_file)
    assert is_valid is False
    assert bad_line == 2
    assert "Manipulación detectada" in error


def test_audit_tamper_detection_line_deleted(tmp_path):
    log_file = tmp_path / "deletion_test.jsonl"
    logger = AuditLogger(log_file)

    logger.log(stage="01-recon", event="event_1", target="target1")
    logger.log(stage="01-recon", event="event_2", target="target2")
    logger.log(stage="01-recon", event="event_3", target="target3")

    # Borrar la línea intermedia
    lines = log_file.read_text(encoding="utf-8").splitlines()
    del lines[1]
    log_file.write_text("\n".join(lines) + "\n", encoding="utf-8")

    is_valid, bad_line, error = verify_audit_file(log_file)
    assert is_valid is False
    assert bad_line == 2
    assert "Rotura de cadena" in error
