"""Módulo de acceso a base de datos y migraciones versionadas.

Aplica migraciones, fuerza PRAGMA foreign_keys=ON y provee métodos seguros
para la gestión del ciclo de vida de activos y hallazgos.
"""

from __future__ import annotations

import hashlib
import sqlite3
from pathlib import Path


class KillSwitchActiveError(Exception):
    """Lanzada cuando el Kill Switch está activado."""


def check_kill_switch(root_dir: str | Path = ".") -> bool:
    """Verifica si existe el archivo STOP de parada de emergencia."""
    stop_file = Path(root_dir) / "STOP"
    return stop_file.exists()


class Database:
    def __init__(self, db_path: str | Path = "state/pipeline.db"):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)

    def get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON;")
        return conn

    def migrate(self, migrations_dir: str | Path = "state/migrations") -> list[str]:
        """Aplica todas las migraciones SQL pendientes en orden cronológico."""
        mig_dir = Path(migrations_dir)
        if not mig_dir.exists():
            return []

        applied = []
        sql_files = sorted(mig_dir.glob("*.sql"))

        with self.get_connection() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS _schema_migrations (
                    version TEXT PRIMARY KEY,
                    applied_at TEXT NOT NULL DEFAULT (datetime('now'))
                )
                """
            )

            existing_rows = conn.execute("SELECT version FROM _schema_migrations").fetchall()
            applied_versions = {row["version"] for row in existing_rows}

            for file in sql_files:
                version_name = file.name
                if version_name not in applied_versions:
                    with open(file, "r", encoding="utf-8") as f:
                        sql_script = f.read()

                    conn.executescript(sql_script)
                    conn.execute(
                        "INSERT INTO _schema_migrations (version) VALUES (?)",
                        (version_name,),
                    )
                    applied.append(version_name)

        return applied

    def create_asset(
        self,
        program_id: str,
        asset_type: str,
        value: str,
        in_scope: bool = True,
        metadata: str | None = None,
    ) -> int:
        with self.get_connection() as conn:
            cur = conn.execute(
                """
                INSERT INTO assets (program_id, asset_type, value, in_scope, metadata)
                VALUES (?, ?, ?, ?, ?)
                RETURNING id
                """,
                (program_id, asset_type, value, 1 if in_scope else 0, metadata),
            )
            row = cur.fetchone()
            return row["id"]

    def create_finding(
        self,
        program_id: str,
        title: str,
        severity: str,
        asset_id: int | None = None,
        description: str | None = None,
        proof_of_concept: str | None = None,
        cvss: float | None = None,
        cve: str | None = None,
        tool_source: str | None = None,
    ) -> int:
        with self.get_connection() as conn:
            cur = conn.execute(
                """
                INSERT INTO findings (
                    program_id, asset_id, title, severity, description,
                    proof_of_concept, cvss, cve, tool_source, status, verified_by_human
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'discovered', 0)
                RETURNING id
                """,
                (program_id, asset_id, title, severity, description, proof_of_concept, cvss, cve, tool_source),
            )
            row = cur.fetchone()
            return row["id"]

    def approve_finding_human_gate(
        self,
        finding_id: int,
        operator: str,
        poc_content: str,
        notes: str | None = None,
    ) -> None:
        """Procedimiento seguro del Gate Humano:
        1. Calcula el hash criptográfico del PoC.
        2. Inserta el registro inmutable en approvals.
        3. Cambia verified_by_human a 1 y status a 'verified'.
        """
        poc_hash = hashlib.sha256(poc_content.encode("utf-8")).hexdigest()

        with self.get_connection() as conn:
            # 1. Registrar aprobación
            conn.execute(
                """
                INSERT INTO approvals (finding_id, operator, poc_hash, notes)
                VALUES (?, ?, ?, ?)
                """,
                (finding_id, operator, poc_hash, notes),
            )

            # 2. Actualizar finding
            conn.execute(
                """
                UPDATE findings
                SET verified_by_human = 1, status = 'verified', updated_at = datetime('now')
                WHERE id = ?
                """,
                (finding_id,),
            )

    def update_finding_status(self, finding_id: int, new_status: str) -> None:
        """Actualiza el estado de un finding (los triggers de SQLite validarán las restricciones de seguridad)."""
        with self.get_connection() as conn:
            conn.execute(
                """
                UPDATE findings
                SET status = ?, updated_at = datetime('now')
                WHERE id = ?
                """,
                (new_status, finding_id),
            )
