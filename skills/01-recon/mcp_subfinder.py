#!/usr/bin/env python3
"""Wrapper MCP: subfinder ejecutado como skill del pipeline (01-recon).

Soporta invocación JSON-RPC 2.0 sobre stdio mediante StdioMCPClient
con fallback a subproceso directo auditado.
"""

from __future__ import annotations

import json
import subprocess
import sys
from typing import Any

from bbpipeline.audit import AuditLogger
from bbpipeline.contracts import StagePayload
from bbpipeline.mcp import StdioMCPClient
from bbpipeline.ratelimit import check_rate_limit
from bbpipeline.scope import ScopeGuard

TOOL_TIMEOUT_SECONDS = 30


def run_tool(command: list[str], timeout: int = TOOL_TIMEOUT_SECONDS) -> dict[str, Any]:
    proc = subprocess.run(command, capture_output=True, text=True, check=False, timeout=timeout)
    return {
        "command": command,
        "returncode": proc.returncode,
        "stdout": proc.stdout or "",
        "stderr": proc.stderr or "",
    }


def run_via_mcp_stdio(target: str, program_id: str, stage: str, actor: str) -> dict[str, Any]:
    """Invoca la herramienta mediante el protocolo MCP estándar sobre stdio."""
    server_cmd = [sys.executable, "-m", "bbpipeline.mcp_server"]
    with StdioMCPClient(command=server_cmd[0], args=server_cmd[1:], timeout=TOOL_TIMEOUT_SECONDS) as client:
        return client.call_tool(
            name="subfinder_scan",
            arguments={"target": target, "program_id": program_id},
            program_id=program_id,
            stage=stage,
        )


_SCOPE_GUARD = ScopeGuard()
_AUDIT_LOGGER = AuditLogger()


def main() -> int:
    try:
        stage_payload = StagePayload.model_validate_json(sys.stdin.read())
        if not stage_payload.target:
            raise ValueError("StagePayload inválido: falta el campo obligatorio 'target'.")

        _SCOPE_GUARD.validate_target(stage_payload.target, program_id=stage_payload.program_id)
        check_rate_limit(stage_payload.program_id, "subfinder")

        use_direct = stage_payload.parameters.get("direct_exec", False)
        if use_direct:
            output = run_tool(["subfinder", "-d", stage_payload.target], timeout=TOOL_TIMEOUT_SECONDS)
            _AUDIT_LOGGER.log(
                stage=stage_payload.stage,
                event="subfinder_finished",
                target=stage_payload.target or "",
                actor=stage_payload.metadata.actor,
                details=output,
            )
        else:
            output = run_via_mcp_stdio(
                target=stage_payload.target,
                program_id=stage_payload.program_id,
                stage=stage_payload.stage,
                actor=stage_payload.metadata.actor,
            )
    except Exception as e:  # noqa: BLE001
        print(json.dumps({"error": f"Fallo en wrapper subfinder: {e}"}))
        return 1

    print(json.dumps(output))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
