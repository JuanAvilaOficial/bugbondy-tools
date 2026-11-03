import os
import sys

import pytest

from bbpipeline.audit import AuditLogger
from bbpipeline.mcp import StdioMCPClient
from bbpipeline.mcp_server import SecurityMCPServer
from bbpipeline.scope import ScopeViolationError


@pytest.fixture
def mcp_server_client(tmp_path):
    env = dict(os.environ)
    env["MCP_MOCK_MODE"] = "1"
    env["PYTHONPATH"] = "src"

    log_path = tmp_path / "mcp_audit.jsonl"
    logger = AuditLogger(log_path)

    cmd = [sys.executable, "-m", "bbpipeline.mcp_server"]
    client = StdioMCPClient(
        command=cmd[0],
        args=cmd[1:],
        env=env,
        timeout=10.0,
        audit_logger=logger,
    )
    client.start()
    yield client
    client.close()


def test_mcp_client_handshake_and_tools_list(mcp_server_client):
    tools = mcp_server_client.list_tools()
    tool_names = [t["name"] for t in tools]

    assert "subfinder_scan" in tool_names
    assert "amass_enum" in tool_names
    assert "nuclei_scan" in tool_names


def test_mcp_client_call_tool_mock(mcp_server_client):
    result = mcp_server_client.call_tool(
        name="subfinder_scan",
        arguments={"target": "api.example.com", "program_id": "example-program"},
        program_id="example-program",
    )

    assert result.get("isError") is False
    content = result.get("content", [])
    assert len(content) > 0
    assert "api.example.com" in content[0]["text"]


def test_mcp_client_enforces_scope_guard(mcp_server_client):
    # support.example.com está en out_of_scope en config/scope.yaml
    with pytest.raises(ScopeViolationError, match="fuera de alcance"):
        mcp_server_client.call_tool(
            name="subfinder_scan",
            arguments={"target": "support.example.com", "program_id": "example-program"},
            program_id="example-program",
        )


def test_mcp_server_direct_dispatch():
    server = SecurityMCPServer(mock_mode=True)

    # 1. Ping
    ping_resp = server.dispatch({"jsonrpc": "2.0", "id": 99, "method": "ping", "params": {}})
    assert ping_resp == {"jsonrpc": "2.0", "id": 99, "result": {}}

    # 2. Unknown method
    err_resp = server.dispatch({"jsonrpc": "2.0", "id": 100, "method": "non_existent", "params": {}})
    assert err_resp["error"]["code"] == -32601

    # 3. Disallowed template in nuclei_scan
    call_resp = server.dispatch({
        "jsonrpc": "2.0",
        "id": 101,
        "method": "tools/call",
        "params": {
            "name": "nuclei_scan",
            "arguments": {
                "target": "api.example.com",
                "templates": ["malicious/dos_attack.yaml"],
            },
        },
    })
    assert call_resp["result"]["isError"] is True
    assert "allowlist" in call_resp["result"]["content"][0]["text"]
