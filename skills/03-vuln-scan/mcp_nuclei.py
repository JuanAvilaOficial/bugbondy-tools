#!/usr/bin/env python3
"""Wrapper MCP: nuclei ejecutado como skill del pipeline (03-vuln-scan).

Soporta invocación JSON-RPC 2.0 sobre stdio mediante StdioMCPClient
con fallback a subproceso directo auditado.
"""

from __future__ import annotations

import json
import subprocess
import sys
from collections.abc import Callable
from typing import Any

from bbpipeline.audit import AuditLogger
from bbpipeline.contracts import StagePayload
from bbpipeline.mcp import StdioMCPClient
from bbpipeline.ratelimit import check_rate_limit
from bbpipeline.scope import ScopeGuard
from bbpipeline.templates import TemplateAllowlist, TemplateNotAllowedError

TOOL_TIMEOUT_SECONDS = 120


def run_tool(command: list[str], timeout: int = TOOL_TIMEOUT_SECONDS) -> dict[str, Any]:
    proc = subprocess.run(command, capture_output=True, text=True, check=False, timeout=timeout)
    return {
        "command": command,
        "returncode": proc.returncode,
        "stdout": proc.stdout or "",
        "stderr": proc.stderr or "",
    }


def build_nuclei_command(stage_payload: StagePayload, templates: list[str]) -> list[str]:
    command = ["nuclei", "-u", stage_payload.target]
    for template in templates:
        command.extend(["-t", template])
    return command


def run_via_mcp_stdio(
    target: str,
    templates: list[str],
    program_id: str,
    stage: str,
    actor: str,
) -> dict[str, Any]:
    """Invoca la herramienta mediante el protocolo MCP estándar sobre stdio."""
    server_cmd = [sys.executable, "-m", "bbpipeline.mcp_server"]
    with StdioMCPClient(command=server_cmd[0], args=server_cmd[1:], timeout=TOOL_TIMEOUT_SECONDS) as client:
        return client.call_tool(
            name="nuclei_scan",
            arguments={"target": target, "templates": templates, "program_id": program_id},
            program_id=program_id,
            stage=stage,
        )


_SCOPE_GUARD = ScopeGuard()
_AUDIT_LOGGER = AuditLogger()
_ALLOWLIST = TemplateAllowlist()
_RATE_LIMIT_CHECK = check_rate_limit


def execute_scan(
    stage_payload: StagePayload,
    run_tool_fn: Callable[[list[str], int], dict] | None = None,
) -> dict[str, Any]:
    """Ejecuta el scan con ScopeGuard, allowlist de plantillas, rate limit y auditoría."""
    if not stage_payload.target:
        raise ValueError("La etapa de escaneo requiere el parámetro 'target'.")

    _SCOPE_GUARD.validate_target(stage_payload.target, program_id=stage_payload.program_id)

    templates: list[str] = list((stage_payload.parameters or {}).get("templates") or [])
    if not templates:
        raise ValueError("La etapa de escaneo requiere el parámetro 'templates'.")

    for template in templates:
        _ALLOWLIST.validate_template(template)

    _RATE_LIMIT_CHECK(stage_payload.program_id, "nuclei")

    use_mcp = (stage_payload.parameters or {}).get("use_mcp", False)
    if use_mcp and run_tool_fn is None:
        return run_via_mcp_stdio(
            target=stage_payload.target,
            templates=templates,
            program_id=stage_payload.program_id,
            stage=stage_payload.stage,
            actor=stage_payload.metadata.actor,
        )

    output = (run_tool_fn or run_tool)(build_nuclei_command(stage_payload, templates), TOOL_TIMEOUT_SECONDS)
    _AUDIT_LOGGER.log(
        stage=stage_payload.stage,
        event="nuclei_scan_completed",
        target=stage_payload.target or "",
        actor=stage_payload.metadata.actor,
        details=output,
    )
    return output


def main() -> int:
    try:
        stage_payload = StagePayload.model_validate_json(sys.stdin.read())
        if not stage_payload.target:
            raise ValueError("StagePayload inválido: falta el campo obligatorio 'target'.")
        output = execute_scan(stage_payload)
    except TemplateNotAllowedError as e:
        print(json.dumps({"error": str(e)}))
        return 1
    except Exception as e:  # noqa: BLE001
        print(json.dumps({"error": f"Fallo escaneo nuclei: {e}"}))
        return 1

    print(json.dumps(output))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
