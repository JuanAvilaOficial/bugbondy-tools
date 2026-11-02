"""Logger de auditoría con encadenamiento criptográfico por hash (SHA-256).

Garantiza la detección de manipulaciones (adiciones no autorizadas, borrados o
modificaciones de líneas previas) en logs/audit.jsonl.
"""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

GENESIS_HASH = "0000000000000000000000000000000000000000000000000000000000000000"


class AuditIntegrityError(Exception):
    """Lanzada cuando se detecta una inconsistencia en la cadena de auditoría."""


def canonical_json(data: dict[str, Any]) -> str:
    """Serializa un diccionario en formato JSON canónico y determinista."""
    return json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def compute_entry_hash(entry_without_hash: dict[str, Any]) -> str:
    """Calcula el hash SHA-256 de una entrada de auditoría."""
    canonical = canonical_json(entry_without_hash)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


class AuditLogger:
    def __init__(self, log_path: str | Path = "logs/audit.jsonl"):
        self.log_path = Path(log_path)
        self.log_path.parent.mkdir(parents=True, exist_ok=True)

    def get_last_hash(self) -> str:
        """Obtiene el hash de la última línea registrada o GENESIS_HASH si el archivo está vacío."""
        if not self.log_path.exists() or self.log_path.stat().st_size == 0:
            return GENESIS_HASH

        last_line = None
        with open(self.log_path, "r", encoding="utf-8") as f:
            for line in f:
                line_str = line.strip()
                if line_str:
                    last_line = line_str

        if not last_line:
            return GENESIS_HASH

        try:
            parsed = json.loads(last_line)
            return parsed.get("hash", GENESIS_HASH)
        except json.JSONDecodeError:
            return GENESIS_HASH

    def log(
        self,
        stage: str,
        event: str,
        target: str,
        details: dict[str, Any] | None = None,
        actor: str = "agent",
    ) -> dict[str, Any]:
        """Registra un evento encadenado al hash previo."""
        prev_hash = self.get_last_hash()
        timestamp = datetime.now(UTC).isoformat()

        entry_payload: dict[str, Any] = {
            "timestamp": timestamp,
            "stage": stage,
            "event": event,
            "target": target,
            "actor": actor,
            "details": details or {},
            "prev_hash": prev_hash,
        }

        entry_hash = compute_entry_hash(entry_payload)
        full_entry = dict(entry_payload)
        full_entry["hash"] = entry_hash

        line_to_write = canonical_json(full_entry) + "\n"

        with open(self.log_path, "a", encoding="utf-8") as f:
            f.write(line_to_write)

        return full_entry

    def verify_chain(self) -> tuple[bool, int, str | None]:
        """Verifica la integridad criptográfica de todo el archivo de auditoría."""
        return verify_audit_file(self.log_path)


def verify_audit_file(log_path: str | Path) -> tuple[bool, int, str | None]:
    """Valida la cadena completa de hashes en un archivo audit.jsonl."""
    path = Path(log_path)
    if not path.exists():
        return False, 0, f"El archivo {path} no existe."

    expected_prev_hash = GENESIS_HASH
    line_number = 0

    with open(path, "r", encoding="utf-8") as f:
        for raw_line in f:
            line_str = raw_line.strip()
            if not line_str:
                continue

            line_number += 1
            try:
                entry = json.loads(line_str)
            except json.JSONDecodeError as e:
                return False, line_number, f"Línea {line_number}: JSON corrupto: {e}"

            recorded_hash = entry.get("hash")
            recorded_prev = entry.get("prev_hash")

            if recorded_prev != expected_prev_hash:
                return (
                    False,
                    line_number,
                    f"Línea {line_number}: Rotura de cadena. prev_hash ({recorded_prev}) != hash esperado ({expected_prev_hash})",
                )

            # Recomputar hash omitiendo la clave 'hash'
            entry_copy = {k: v for k, v in entry.items() if k != "hash"}
            calculated_hash = compute_entry_hash(entry_copy)

            if calculated_hash != recorded_hash:
                return (
                    False,
                    line_number,
                    f"Línea {line_number}: Manipulación detectada. hash ({recorded_hash}) != calculado ({calculated_hash})",
                )

            expected_prev_hash = recorded_hash

    return True, line_number, None
