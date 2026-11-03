"""Cliente MCP (Model Context Protocol) sobre stdio mediante JSON-RPC 2.0.

Implementa el protocolo estándar MCP para la invocación de herramientas de
seguridad a través de subprocesos stdin/stdout, garantizando:
1. Handshake formal JSON-RPC 2.0 (initialize, notifications/initialized).
2. Descubrimiento de herramientas mediante tools/list.
3. Invocación segura mediante tools/call con guardrails técnicos:
   - Validación obligatoria de alcance (ScopeGuard fail-closed).
   - Control de velocidad persistente (check_rate_limit fail-closed).
   - Registro inmutable encadenado (AuditLogger).
"""

from __future__ import annotations

import json
import subprocess
import threading
from typing import Any, Self

from bbpipeline.audit import AuditLogger
from bbpipeline.ratelimit import check_rate_limit
from bbpipeline.scope import ScopeGuard

MCP_PROTOCOL_VERSION = "2024-11-05"


class MCPError(Exception):
    """Error devuelto por el servidor MCP en JSON-RPC 2.0."""

    def __init__(self, code: int, message: str, data: Any = None) -> None:
        self.code = code
        self.message = message
        self.data = data
        super().__init__(f"MCP Error [{code}]: {message} (data={data})")


class StdioMCPClient:
    """Cliente JSON-RPC 2.0 para servidores MCP ejecutados sobre stdio."""

    def __init__(
        self,
        command: str,
        args: list[str] | None = None,
        env: dict[str, str] | None = None,
        timeout: float = 30.0,
        scope_guard: ScopeGuard | None = None,
        audit_logger: AuditLogger | None = None,
    ) -> None:
        self.command = command
        self.args = args or []
        self.env = env
        self.timeout = timeout
        self.scope_guard = scope_guard or ScopeGuard()
        self.audit_logger = audit_logger or AuditLogger()

        self._process: subprocess.Popen[str] | None = None
        self._next_id = 1
        self._lock = threading.Lock()
        self._server_info: dict[str, Any] = {}
        self._server_capabilities: dict[str, Any] = {}
        self._initialized = False

    def start(self) -> None:
        """Inicia el subproceso del servidor MCP y realiza el handshake de inicialización."""
        if self._process is not None:
            return

        cmd = [self.command, *self.args]
        self._process = subprocess.Popen(
            cmd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
            env=self.env,
        )

        # Handshake: initialize
        init_result = self.send_request(
            method="initialize",
            params={
                "protocolVersion": MCP_PROTOCOL_VERSION,
                "capabilities": {},
                "clientInfo": {"name": "bbpipeline-client", "version": "0.1.0"},
            },
        )
        self._server_info = init_result.get("serverInfo", {})
        self._server_capabilities = init_result.get("capabilities", {})

        # Handshake: notification initialized
        self.send_notification("notifications/initialized")
        self._initialized = True

    def _read_response(self, expected_id: int) -> dict[str, Any]:
        """Lee líneas de stdout hasta encontrar la respuesta con el id esperado."""
        if self._process is None or self._process.stdout is None:
            raise RuntimeError("El proceso del servidor MCP no está corriendo.")

        while True:
            line = self._process.stdout.readline()
            if not line:
                returncode = self._process.poll()
                stderr = self._process.stderr.read() if self._process.stderr else ""
                raise RuntimeError(
                    f"El servidor MCP cerró stdout inesperadamente (exit code: {returncode}). stderr: {stderr}"
                )

            line_str = line.strip()
            if not line_str:
                continue

            try:
                msg = json.loads(line_str)
            except json.JSONDecodeError:
                continue

            if msg.get("id") == expected_id:
                if "error" in msg:
                    err = msg["error"]
                    raise MCPError(
                        code=err.get("code", -32000),
                        message=err.get("message", "Unknown error"),
                        data=err.get("data"),
                    )
                return msg.get("result", {})

    def send_request(self, method: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        """Envía una petición JSON-RPC 2.0 y espera la respuesta correspondiente."""
        if self._process is None or self._process.stdin is None:
            raise RuntimeError("El cliente MCP no ha sido iniciado.")

        with self._lock:
            msg_id = self._next_id
            self._next_id += 1

            payload = {
                "jsonrpc": "2.0",
                "id": msg_id,
                "method": method,
                "params": params or {},
            }
            msg_line = json.dumps(payload) + "\n"
            self._process.stdin.write(msg_line)
            self._process.stdin.flush()

            return self._read_response(msg_id)

    def send_notification(self, method: str, params: dict[str, Any] | None = None) -> None:
        """Envía una notificación JSON-RPC 2.0 (sin id ni respuesta)."""
        if self._process is None or self._process.stdin is None:
            raise RuntimeError("El cliente MCP no ha sido iniciado.")

        with self._lock:
            payload = {
                "jsonrpc": "2.0",
                "method": method,
                "params": params or {},
            }
            self._process.stdin.write(json.dumps(payload) + "\n")
            self._process.stdin.flush()

    def list_tools(self) -> list[dict[str, Any]]:
        """Descubre las herramientas expuestas por el servidor MCP (tools/list)."""
        if not self._initialized:
            self.start()
        result = self.send_request("tools/list", {})
        return result.get("tools", [])

    def call_tool(
        self,
        name: str,
        arguments: dict[str, Any],
        program_id: str | None = None,
        stage: str = "tools",
        validate_scope: bool = True,
        enforce_rate_limit: bool = True,
    ) -> dict[str, Any]:
        """Invoca una herramienta MCP vía tools/call con guardrails de alcance y rate limit."""
        if not self._initialized:
            self.start()

        target = str(arguments.get("target") or arguments.get("url") or arguments.get("domain") or "")

        # Guardrail 1: ScopeGuard fail-closed
        if validate_scope and target:
            self.scope_guard.validate_target(target, program_id=program_id)

        # Guardrail 2: Rate Limit fail-closed
        if enforce_rate_limit:
            check_rate_limit(program_id=program_id, tool=name, enforce=True)

        # Invocación MCP
        result = self.send_request("tools/call", {"name": name, "arguments": arguments})

        # Guardrail 3: Registro inmutable en auditoría
        self.audit_logger.log(
            stage=stage,
            event=f"mcp_tool_called:{name}",
            target=target or "local",
            actor="agent",
            details={"tool": name, "arguments": arguments, "isError": result.get("isError", False)},
        )

        return result

    def close(self) -> None:
        """Cierra la conexión con el servidor MCP y libera recursos."""
        if self._process is not None:
            try:
                if self._process.stdin and not self._process.stdin.closed:
                    self._process.stdin.close()
                self._process.terminate()
                self._process.wait(timeout=2.0)
            except (OSError, subprocess.TimeoutExpired):
                self._process.kill()
            finally:
                self._process = None
                self._initialized = False

    def __enter__(self) -> Self:
        self.start()
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: object,
    ) -> None:
        self.close()
