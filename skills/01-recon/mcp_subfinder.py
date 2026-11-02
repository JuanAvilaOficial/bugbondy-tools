#!/usr/bin/env python3
"""Wrapper MCP: subfinder ejecutado como skill del pipeline (01-recon)."""

from __future__ import annotations

import json
import subprocess
import sys

from bbpipeline.audit import AuditLogger
from bbpipeline.contracts import StagePayload
from bbpipeline.ratelimit import check_rate_limit
from bbpipeline.scope import ScopeGuard

TOOL_TIMEOUT_SECONDS = 30


def run_tool(command: list[str], timeout: int = TOOL_TIMEOUT_SECONDS) -> dict:
    proc = subprocess.run(command, capture_output=True, text=True, check=False, timeout=timeout)
    return {"command": command, "returncode": proc.returncode, "stdout": proc.stdout or "", "stderr": proc.stderr or ""}


_SCOPE_GUARD = ScopeGuard()
_AUDIT_LOGGER = AuditLogger()


def main() -> int:
    try:
        stage_payload = StagePayload.model_validate_json(sys.stdin.read())
        if not stage_payload.target:
            raise ValueError("StagePayload invalido: falta el campo obligatorio 'target'.")
        _SCOPE_GUARD.validate_target(stage_payload.target, program_id=stage_payload.program_id)
        check_rate_limit(stage_payload.program_id, "subfinder")
        output = run_tool(["subfinder", "-d", stage_payload.target], timeout=TOOL_TIMEOUT_SECONDS)
    except Exception as e:  # noqa: BLE001
        print(json.dumps({"error": f"Fallo en wrapper subfinder: {e}"}))
        return 1

    _AUDIT_LOGGER.log(
        stage=stage_payload.stage,
        event="subfinder_finished",
        target=stage_payload.target or "",
        actor=stage_payload.metadata.actor,
        details=output,
    )

    print(json.dumps(output))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
