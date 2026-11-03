"""Servidor MCP (Model Context Protocol) sobre stdio para la gestión de clientes en Intigriti.

Permite que el agente de IA o el operador humano:
1. Liste los programas/clientes autorizados en su cuenta de Intigriti.
2. Obtenga información detallada sobre las directivas de seguridad y requerimientos de cada cliente.
3. Seleccione un cliente específico, restringiendo y sincronizando de inmediato el alcance del pipeline.
4. Consulte el cliente actualmente seleccionado.
"""

from __future__ import annotations

import json
import sys
from typing import Any

from bbpipeline.intigriti import (
    IntigritiAPIError,
    IntigritiAuthError,
    IntigritiClient,
    IntigritiNotFoundError,
)
from bbpipeline.scope import ScopeGuard

SERVER_NAME = "bbpipeline-intigriti-mcp"
SERVER_VERSION = "0.1.0"
PROTOCOL_VERSION = "2024-11-05"

TOOLS_REGISTRY: list[dict[str, Any]] = [
    {
        "name": "intigriti_list_programs",
        "description": "Lista los programas y clientes de Bug Bounty accesibles en la cuenta de Intigriti.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "limit": {"type": "integer", "description": "Cantidad máxima de programas a devolver (default: 20)", "default": 20},
                "offset": {"type": "integer", "description": "Desplazamiento para paginación (default: 0)", "default": 0},
                "status": {"type": "string", "description": "Filtro opcional por estado (ej. 'Open', 'Suspended')"},
            },
        },
    },
    {
        "name": "intigriti_get_program_info",
        "description": "Obtiene la información detallada, directivas y requisitos de testing de un programa de Intigriti.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "program_id": {"type": "string", "description": "ID o handle del programa (ej. 'intigriti-sandbox' o UUID)"},
            },
            "required": ["program_id"],
        },
    },
    {
        "name": "intigriti_select_client",
        "description": "Selecciona formalmente un cliente de Intigriti como objetivo del pipeline, sincronizando su alcance oficial (in-scope / out-of-scope) de forma estricta y fail-closed.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "program_id": {"type": "string", "description": "ID o handle del programa en Intigriti a seleccionar"},
                "scope_path": {"type": "string", "description": "Ruta a scope.yaml (default: config/scope.yaml)", "default": "config/scope.yaml"},
            },
            "required": ["program_id"],
        },
    },
    {
        "name": "intigriti_get_active_client",
        "description": "Devuelve el cliente de Intigriti actualmente activo y configurado en el pipeline.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "scope_path": {"type": "string", "description": "Ruta a scope.yaml (default: config/scope.yaml)", "default": "config/scope.yaml"},
            },
        },
    },
]


class IntigritiMCPServer:
    """Servidor MCP JSON-RPC 2.0 sobre stdio para Intigriti."""

    def __init__(
        self,
        client: IntigritiClient | None = None,
        scope_path: str = "config/scope.yaml",
        db_path: str = "state/pipeline.db",
    ) -> None:
        self.client = client or IntigritiClient()
        self.scope_path = scope_path
        self.db_path = db_path

    def execute_tool(self, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        """Ejecuta la herramienta solicitada."""
        if name == "intigriti_list_programs":
            limit = int(arguments.get("limit", 20))
            offset = int(arguments.get("offset", 0))
            status = arguments.get("status")
            programs = self.client.list_programs(limit=limit, offset=offset, status=status)
            summaries = []
            for p in programs:
                summaries.append({
                    "id": p.get("id"),
                    "handle": p.get("handle"),
                    "name": p.get("name"),
                    "status": p.get("status", {}).get("value") if isinstance(p.get("status"), dict) else p.get("status"),
                    "confidentiality": p.get("confidentialityLevel", {}).get("value") if isinstance(p.get("confidentialityLevel"), dict) else None,
                    "min_bounty": p.get("minBounty"),
                    "max_bounty": p.get("maxBounty"),
                    "industry": p.get("industry"),
                })
            return {"status": "success", "count": len(summaries), "programs": summaries}

        if name == "intigriti_get_program_info":
            program_id = arguments.get("program_id")
            if not program_id:
                raise ValueError("Se requiere 'program_id'.")
            details = self.client.get_program_details(program_id)
            domains = self.client.get_program_domains(program_id)
            roe = self.client.get_program_roe(program_id)
            reqs = self.client.extract_testing_requirements(program_id)
            return {
                "status": "success",
                "id": details.get("id"),
                "handle": details.get("handle"),
                "name": details.get("name"),
                "total_domains": len(domains),
                "safe_harbour": roe.get("safeHarbour", False),
                "testing_requirements": reqs,
                "description": roe.get("description", ""),
            }

        if name == "intigriti_select_client":
            program_id = arguments.get("program_id")
            if not program_id:
                raise ValueError("Se requiere 'program_id'.")
            scope_target = arguments.get("scope_path", self.scope_path)
            scope_obj = self.client.sync_program_to_pipeline(
                program_id=program_id,
                scope_path=scope_target,
                db_path=self.db_path,
            )
            reqs = self.client.extract_testing_requirements(program_id)
            return {
                "status": "success",
                "message": f"Cliente '{scope_obj.name}' seleccionado y sincronizado con éxito.",
                "program_id": scope_obj.id,
                "platform": scope_obj.platform,
                "in_scope_count": len(scope_obj.in_scope_targets),
                "out_of_scope_count": len(scope_obj.out_of_scope_targets),
                "in_scope_sample": [r.target for r in scope_obj.in_scope_targets[:5]],
                "testing_requirements": reqs,
            }

        if name == "intigriti_get_active_client":
            scope_target = arguments.get("scope_path", self.scope_path)
            try:
                guard = ScopeGuard(scope_target)
                intigriti_programs = [p for p in guard.config.programs if p.platform == "intigriti"]
                if not intigriti_programs:
                    return {
                        "status": "none_selected",
                        "message": "No hay ningún cliente de Intigriti activo en el archivo de alcance.",
                    }
                active = intigriti_programs[0]
                return {
                    "status": "active",
                    "id": active.id,
                    "name": active.name,
                    "in_scope_targets": [r.target for r in active.in_scope_targets],
                    "out_of_scope_targets": [r.target for r in active.out_of_scope_targets],
                }
            except Exception as e:  # noqa: BLE001
                return {"status": "error", "message": f"Error leyendo alcance activo: {e}"}

        raise ValueError(f"Herramienta desconocida: '{name}'")

    def handle_tools_call(self, req_id: Any, params: dict[str, Any]) -> dict[str, Any]:
        """Procesa una llamada tools/call de JSON-RPC 2.0."""
        name = params.get("name", "")
        arguments = params.get("arguments", {})

        try:
            output = self.execute_tool(name, arguments)
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "content": [{"type": "text", "text": json.dumps(output, ensure_ascii=False)}],
                    "isError": False,
                },
            }
        except (IntigritiAPIError, IntigritiAuthError, IntigritiNotFoundError, ValueError) as e:
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "content": [{"type": "text", "text": f"Error ejecutando herramienta '{name}': {e}"}],
                    "isError": True,
                },
            }
        except Exception as e:  # noqa: BLE001
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "error": {"code": -32603, "message": f"Internal error: {e}"},
            }

    def dispatch(self, request_raw: str) -> str | None:
        """Enruta y responde a mensajes JSON-RPC 2.0 individuales."""
        line = request_raw.strip()
        if not line:
            return None

        try:
            req = json.loads(line)
        except json.JSONDecodeError:
            return json.dumps({"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": "Parse error"}})

        req_id = req.get("id")
        method = req.get("method")

        # Handshake MCP
        if method == "initialize":
            return json.dumps({
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "protocolVersion": PROTOCOL_VERSION,
                    "capabilities": {"tools": {}},
                    "serverInfo": {"name": SERVER_NAME, "version": SERVER_VERSION},
                },
            })

        if method == "notifications/initialized":
            return None

        if method == "tools/list":
            return json.dumps({
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {"tools": TOOLS_REGISTRY},
            })

        if method == "tools/call":
            params = req.get("params", {})
            res = self.handle_tools_call(req_id, params)
            return json.dumps(res)

        return json.dumps({
            "jsonrpc": "2.0",
            "id": req_id,
            "error": {"code": -32601, "message": f"Method not found: '{method}'"},
        })

    def run_stdio(self) -> None:
        """Loop de ejecución principal sobre stdin/stdout."""
        for line in sys.stdin:
            response = self.dispatch(line)
            if response:
                sys.stdout.write(response + "\n")
                sys.stdout.flush()


def main() -> int:
    server = IntigritiMCPServer()
    server.run_stdio()
    return 0


if __name__ == "__main__":
    sys.exit(main())
