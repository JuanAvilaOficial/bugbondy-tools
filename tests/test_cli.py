import argparse
import subprocess
import sys

from bbpipeline import cli as cli_module


def run_cli(*args):
    cmd = [sys.executable, "-m", "bbpipeline.cli", *args]
    return subprocess.run(cmd, check=False, capture_output=True, text=True)


def test_cli_scope_check():
    # En scope
    res = run_cli("check-scope", "api.example.com")
    assert res.returncode == 0
    assert "IN SCOPE" in res.stdout

    # Fuera de scope (support.example.com está explícitamente en out_of_scope)
    res_oos = run_cli("check-scope", "support.example.com")
    assert res_oos.returncode == 1
    assert "OUT OF SCOPE" in res_oos.stderr


def test_cli_audit_verify():
    res = run_cli("audit", "verify", "--log-path", "logs/audit.jsonl")
    assert res.returncode == 0
    assert "Auditoría íntegra y verificada" in res.stdout


def test_cli_doctor(capsys):
    res = cli_module.cmd_doctor(argparse.Namespace())
    captured = capsys.readouterr()
    assert "Doctor" in captured.out
    assert res in (0, 1)


def test_cli_migrate_and_approve(tmp_path):
    db_path = str(tmp_path / "cli_test.db")
    log_path = str(tmp_path / "cli_audit.jsonl")

    # Ejecutar migración vía CLI
    res_mig = run_cli("migrate", "--db-path", db_path)
    assert res_mig.returncode == 0
    assert "Migraciones aplicadas" in res_mig.stdout

    # Crear finding directamente con python db para luego aprobarlo vía CLI
    from bbpipeline.db import Database
    db = Database(db_path)
    finding_id = db.create_finding(
        program_id="example-program",
        title="Command Injection",
        severity="critical",
    )

    # Aprobar con CLI
    res_app = run_cli(
        "approve",
        str(finding_id),
        "--operator",
        "human_analyst",
        "--poc",
        "; whoami",
        "--notes",
        "Validado en laboratorio",
        "--db-path",
        db_path,
        "--log-path",
        log_path,
    )
    assert res_app.returncode == 0
    assert "Gate Humano Aprobado" in res_app.stdout

    # Verificar que el log de auditoría se generó correctamente
    res_ver = run_cli("audit", "verify", "--log-path", log_path)
    assert res_ver.returncode == 0
