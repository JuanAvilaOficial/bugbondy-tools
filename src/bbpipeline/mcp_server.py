"""Servidor MCP (Model Context Protocol) sobre stdio para herramientas de seguridad.

Expone las herramientas del Bug Bounty Pipeline (subfinder, amass, nuclei)
como herramientas estándar MCP invocables por cualquier agente o cliente
compatible con el protocolo JSON-RPC 2.0 sobre stdin/stdout.
"""

from __future__ import annotations

import json
import subprocess
import sys
from typing import Any

from bbpipeline.scope import ScopeGuard, ScopeViolationError
from bbpipeline.templates import TemplateAllowlist, TemplateNotAllowedError

SERVER_NAME = "bbpipeline-security-mcp"
SERVER_VERSION = "0.1.0"
PROTOCOL_VERSION = "2024-11-05"

TOOLS_REGISTRY: list[dict[str, Any]] = [
    {
        "name": "subfinder_scan",
        "description": "Descubrimiento de subdominios para un dominio objetivo in-scope.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Dominio objetivo (ej. example.com)"},
                "program_id": {"type": "string", "description": "ID del programa en scope.yaml"},
            },
            "required": ["target"],
        },
    },
    {
        "name": "amass_enum",
        "description": "Enumeración y mapeo de infraestructura para un dominio objetivo in-scope.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Dominio objetivo (ej. example.com)"},
                "program_id": {"type": "string", "description": "ID del programa en scope.yaml"},
            },
            "required": ["target"],
        },
    },
    {
        "name": "nuclei_scan",
        "description": "Escaneo de vulnerabilidades mediante plantillas Nuclei aprobadas en la allowlist.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "URL o target objetivo in-scope"},
                "templates": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Lista de rutas de plantillas Nuclei autorizadas",
                },
                "program_id": {"type": "string", "description": "ID del programa en scope.yaml"},
            },
            "required": ["target", "templates"],
        },
    },
]


class SecurityMCPServer:
    def __init__(
        self,
        scope_guard: ScopeGuard | None = None,
        allowlist: TemplateAllowlist | None = None,
        mock_mode: bool = False,
    ) -> None:
        import os

        self.scope_guard = scope_guard or ScopeGuard()
        self.allowlist = allowlist or TemplateAllowlist()
        self.mock_mode = mock_mode or os.environ.get("MCP_MOCK_MODE") == "1"

    def handle_initialize(self, req_id: Any, params: dict[str, Any]) -> dict[str, Any]:
        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "result": {
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": {
                    "tools": {"listChanged": False},
                },
                "serverInfo": {
                    "name": SERVER_NAME,
                    "version": SERVER_VERSION,
                },
            },
        }

    def handle_tools_list(self, req_id: Any, params: dict[str, Any]) -> dict[str, Any]:
        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "result": {
                "tools": TOOLS_REGISTRY,
            },
        }

    def execute_tool(self, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        target = str(arguments.get("target") or "")
        program_id = arguments.get("program_id")

        # 1. Defensa en profundidad: ScopeGuard
        if target:
            self.scope_guard.validate_target(target, program_id=program_id)

        if name == "subfinder_scan":
            cmd = ["subfinder", "-d", target]
            if self.mock_mode:
                return {"tool": name, "target": target, "status": "success", "subdomains": [f"api.{target}", f"www.{target}"]}
            proc = subprocess.run(cmd, capture_output=True, text=True, check=False, timeout=60)
            return {"tool": name, "target": target, "returncode": proc.returncode, "stdout": proc.stdout, "stderr": proc.stderr}

        if name == "amass_enum":
            cmd = ["amass", "enum", "-d", target]
            if self.mock_mode:
                return {"tool": name, "target": target, "status": "success", "assets": [f"{target}:443"]}
            proc = subprocess.run(cmd, capture_output=True, text=True, check=False, timeout=60)
            return {"tool": name, "target": target, "returncode": proc.returncode, "stdout": proc.stdout, "stderr": proc.stderr}

        if name == "nuclei_scan":
            templates = list(arguments.get("templates") or [])
            if not templates:
                raise ValueError("Se requiere al menos una plantilla para nuclei_scan.")
            for tmpl in templates:
                self.allowlist.validate_template(tmpl)

            cmd = ["nuclei", "-u", target]
            for tmpl in templates:
                cmd.extend(["-t", tmpl])

            if self.mock_mode:
                return {"tool": name, "target": target, "templates": templates, "status": "success", "matches": []}
            proc = subprocess.run(cmd, capture_output=True, text=True, check=False, timeout=120)
            return {"tool": name, "target": target, "returncode": proc.returncode, "stdout": proc.stdout, "stderr": proc.stderr}

        raise ValueError(f"Herramienta desconocida: '{name}'")

    def handle_tools_call(self, req_id: Any, params: dict[str, Any]) -> dict[str, Any]:
        name = params.get("name", "")
        arguments = params.get("arguments", {})

        try:
            output = self.execute_tool(name, arguments)
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "content": [{"type": "text", "text": json.dumps(output)}],
                    "isError": False,
                },
            }
        except (ScopeViolationError, TemplateNotAllowedError, ValueError) as e:
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "content": [{"type": "text", "text": f"Error de seguridad/parámetro: {e}"}],
                    "isError": True,
                },
            }
        except Exception as e:  # noqa: BLE001
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "error": {
                    "code": -32603,
                    "message": f"Fallo interno en ejecución de herramienta: {e}",
                },
            }

    def dispatch(self, request_data: dict[str, Any]) -> dict[str, Any] | None:
        method = request_data.get("method")
        req_id = request_data.get("id")
        params = request_data.get("params") or {}

        # Notificaciones (sin id ni respuesta requerida)
        if req_id is None:
            return None

        if method == "initialize":
            return self.handle_initialize(req_id, params)
        if method == "tools/list":
            return self.handle_tools_list(req_id, params)
        if method == "tools/call":
            return self.handle_tools_call(req_id, params)
        if method == "ping":
            return {"jsonrpc": "2.0", "id": req_id, "result": {}}

        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "error": {"code": -32601, "message": f"Método no encontrado: '{method}'"},
        }

    def run_stdio(self) -> None:
        """Loop principal del servidor MCP sobre standard input/output."""
        for line in sys.stdin:
            line_str = line.strip()
            if not line_str:
                continue

            try:
                request_data = json.loads(line_str)
            except json.JSONDecodeError as e:
                resp = {
                    "jsonrpc": "2.0",
                    "id": None,
                    "error": {"code": -32700, "message": f"Parse error: {e}"},
                }
                sys.stdout.write(json.dumps(resp) + "\n")
                sys.stdout.flush()
                continue

            response = self.dispatch(request_data)
            if response is not None:
                sys.stdout.write(json.dumps(response) + "\n")
                sys.stdout.flush()


def main() -> int:
    server = SecurityMCPServer()
    server.run_stdio()
    return 0


if __name__ == "__main__":
    sys.exit(main())
