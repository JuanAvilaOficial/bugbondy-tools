import sqlite3

import pytest

from bbpipeline.db import Database, check_kill_switch


@pytest.fixture
def temp_db(tmp_path):
    db_file = tmp_path / "test_pipeline.db"
    db = Database(db_file)
    db.migrate("state/migrations")
    return db


def test_cannot_insert_pre_verified_finding(temp_db):
    # Trigger 3: No se puede insertar con verified_by_human=1 directamente
    with pytest.raises(sqlite3.IntegrityError, match="GATE VIOLATION"), temp_db.get_connection() as conn:
        conn.execute(
            """
            INSERT INTO findings (program_id, title, severity, verified_by_human)
            VALUES ('example-program', 'Fake Vuln', 'high', 1)
            """
        )


def test_cannot_set_reported_without_human_verification(temp_db):
    finding_id = temp_db.create_finding(
        program_id="example-program",
        title="SQL Injection",
        severity="critical",
        description="id parameter vulnerable",
        proof_of_concept="' OR 1=1--",
    )

    # Intentar pasar a 'reported' cuando verified_by_human es 0 -> debe fallar por Trigger 1
    with pytest.raises(sqlite3.IntegrityError, match="GATE VIOLATION"):
        temp_db.update_finding_status(finding_id, "reported")

    # Intentar pasar a 'submitted' sin verificación -> debe fallar
    with pytest.raises(sqlite3.IntegrityError, match="GATE VIOLATION"):
        temp_db.update_finding_status(finding_id, "submitted")


def test_cannot_set_verified_by_human_without_approval_record(temp_db):
    finding_id = temp_db.create_finding(
        program_id="example-program",
        title="XSS Stored",
        severity="medium",
    )

    # Trigger 2: Intentar hacer UPDATE directo sin registro en approvals
    with pytest.raises(sqlite3.IntegrityError, match="GATE VIOLATION"), temp_db.get_connection() as conn:
        conn.execute(
            "UPDATE findings SET verified_by_human = 1 WHERE id = ?",
            (finding_id,),
        )


def test_successful_human_gate_approval(temp_db):
    poc = "<script>alert(1)</script>"
    finding_id = temp_db.create_finding(
        program_id="example-program",
        title="Reflected XSS",
        severity="medium",
        proof_of_concept=poc,
    )

    # Aprobación formal por parte del operador humano a través del método seguro
    temp_db.approve_finding_human_gate(
        finding_id=finding_id,
        operator="sec_operator_alice",
        poc_content=poc,
        notes="Reproducido manualmente en entorno de prueba.",
    )

    with temp_db.get_connection() as conn:
        row = conn.execute("SELECT status, verified_by_human FROM findings WHERE id = ?", (finding_id,)).fetchone()
        assert row["status"] == "verified"
        assert row["verified_by_human"] == 1

        # Ahora que está verificado por humano, sí puede pasar a 'reported' y 'submitted'
        conn.execute("UPDATE findings SET status = 'reported' WHERE id = ?", (finding_id,))
        updated_row = conn.execute("SELECT status FROM findings WHERE id = ?", (finding_id,)).fetchone()
        assert updated_row["status"] == "reported"


def test_approvals_are_immutable(temp_db):
    poc = "payload"
    finding_id = temp_db.create_finding(
        program_id="example-program",
        title="SSRF",
        severity="high",
        proof_of_concept=poc,
    )
    temp_db.approve_finding_human_gate(
        finding_id=finding_id,
        operator="sec_operator_bob",
        poc_content=poc,
    )

    # Intentar modificar el registro de aprobación (Trigger 4)
    with pytest.raises(sqlite3.IntegrityError, match="GOVERNANCE VIOLATION"), temp_db.get_connection() as conn:
        conn.execute(
            "UPDATE approvals SET operator = 'malicious_agent' WHERE finding_id = ?",
            (finding_id,),
        )


def test_kill_switch_detection(tmp_path):
    assert check_kill_switch(tmp_path) is False
    stop_file = tmp_path / "STOP"
    stop_file.touch()
    assert check_kill_switch(tmp_path) is True
