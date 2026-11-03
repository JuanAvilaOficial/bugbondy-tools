import json
import subprocess
import sys
from unittest.mock import MagicMock, patch

import httpx
import pytest

from bbpipeline.db import Database
from bbpipeline.intigriti import (
    IntigritiAuthError,
    IntigritiClient,
    IntigritiNotFoundError,
    get_stored_token,
    save_token,
)
from bbpipeline.intigriti_mcp import IntigritiMCPServer
from bbpipeline.scope import ScopeGuard, ScopeViolationError


def run_cli(*args: str) -> subprocess.CompletedProcess[str]:
    cmd = [sys.executable, "-m", "bbpipeline.cli", *args]
    return subprocess.run(cmd, check=False, capture_output=True, text=True)


def test_token_save_and_retrieve(tmp_path):
    token_file = tmp_path / "credentials.json"
    saved = save_token("test-secret-token-1234", path=token_file)
    assert saved.exists()
    assert (token_file.stat().st_mode & 0o777) == 0o600

    # Leer token
    with (
        patch("bbpipeline.intigriti.CREDENTIALS_FILE", token_file),
        patch.dict("os.environ", {}, clear=True),
    ):
        token = get_stored_token()
        assert token == "test-secret-token-1234"


def test_intigriti_client_mock_listing():
    client = IntigritiClient(mock_mode=True)
    programs = client.list_programs(limit=10)
    assert len(programs) >= 2
    handles = [p["handle"] for p in programs]
    assert "intigriti-sandbox" in handles
    assert "acme-corp" in handles


def test_intigriti_client_mock_details_and_not_found():
    client = IntigritiClient(mock_mode=True)
    details = client.get_program_details("intigriti-sandbox")
    assert details["name"] == "Intigriti Researcher Sandbox"

    with pytest.raises(IntigritiNotFoundError):
        client.get_program_details("non-existent-program")


def test_intigriti_client_url_resolution():
    client = IntigritiClient(mock_mode=True)
    url = "https://app.intigriti.com/researcher/programs/wl/wirelesslogic/preview/detail"

    # Extracción de candidato
    candidate = client.extract_program_candidate(url)
    assert candidate == "wirelesslogic"

    # Obtener detalles pasando la URL completa
    details = client.get_program_details(url)
    assert details["name"] == "Wireless Logic Bug Bounty"
    assert details["handle"] == "wirelesslogic"

    # Construir alcance pasando la URL completa
    scope = client.build_program_scope(url)
    assert scope.id == "wirelesslogic"
    assert "*.wirelesslogic.com" in [r.target for r in scope.in_scope_targets]
    assert "blog.wirelesslogic.com" in [r.target for r in scope.out_of_scope_targets]


def test_intigriti_client_build_program_scope():
    client = IntigritiClient(mock_mode=True)
    scope = client.build_program_scope("intigriti-sandbox")

    assert scope.id == "intigriti-sandbox"
    assert scope.platform == "intigriti"

    in_scope = [r.target for r in scope.in_scope_targets]
    out_of_scope = [r.target for r in scope.out_of_scope_targets]

    assert "*.sandbox.intigriti.net" in in_scope
    assert "https://api.sandbox.intigriti.net" in in_scope
    assert "admin.sandbox.intigriti.net" in out_of_scope


def test_intigriti_client_extract_testing_requirements():
    client = IntigritiClient(mock_mode=True)
    reqs = client.extract_testing_requirements("intigriti-sandbox")
    assert "User-Agent" in reqs
    assert "Request-Header" in reqs
    assert reqs["Request-Header"] == "X-BugBounty-Hacker: researcher"


def test_intigriti_client_sync_program_to_pipeline(tmp_path):
    scope_path = tmp_path / "scope.yaml"
    db_path = tmp_path / "pipeline.db"
    rate_limits_path = tmp_path / "rate-limits.yaml"
    audit_path = tmp_path / "audit.jsonl"

    # Preparar base de datos
    db = Database(db_path)
    db.migrate("state/migrations")

    # Preparar rate-limits inicial
    rate_limits_path.write_text("version: '1.0'\nprograms: {}\n", encoding="utf-8")

    client = IntigritiClient(mock_mode=True)
    synced_scope = client.sync_program_to_pipeline(
        program_id="intigriti-sandbox",
        scope_path=scope_path,
        db_path=db_path,
        rate_limits_path=rate_limits_path,
        audit_path=audit_path,
    )

    assert synced_scope.id == "intigriti-sandbox"
    assert scope_path.exists()

    # Validar que ScopeGuard puede cargar la configuración sincronizada
    guard = ScopeGuard(config_path=scope_path)
    prog = guard.get_program("intigriti-sandbox")
    assert prog.id == "intigriti-sandbox"

    # Targets in-scope permitidos por ScopeGuard
    guard.validate_target("foo.sandbox.intigriti.net", program_id="intigriti-sandbox")
    guard.validate_target("https://api.sandbox.intigriti.net", program_id="intigriti-sandbox")

    # Target out-of-scope debe ser bloqueado fail-closed
    with pytest.raises(ScopeViolationError):
        guard.validate_target("admin.sandbox.intigriti.net", program_id="intigriti-sandbox")

    # Verificar que los activos se insertaron en la base de datos SQLite
    with db.get_connection() as conn:
        rows = conn.execute("SELECT value, in_scope FROM assets WHERE program_id = 'intigriti-sandbox'").fetchall()
        asset_map = {r["value"]: r["in_scope"] for r in rows}
        assert asset_map["*.sandbox.intigriti.net"] == 1
        assert asset_map["admin.sandbox.intigriti.net"] == 0

    # Verificar que audit.jsonl registró el evento
    assert audit_path.exists()
    content = audit_path.read_text(encoding="utf-8")
    assert "intigriti_client_selected" in content


def test_intigriti_client_http_error_handling():
    client = IntigritiClient(token="invalid-token", mock_mode=False)

    # 401 Unauthorized
    mock_resp_401 = MagicMock(spec=httpx.Response)
    mock_resp_401.status_code = 401
    with (
        patch("httpx.Client.get", return_value=mock_resp_401),
        pytest.raises(IntigritiAuthError, match="401"),
    ):
        client.list_programs()

    # 404 Not Found
    mock_resp_404 = MagicMock(spec=httpx.Response)
    mock_resp_404.status_code = 404
    with (
        patch("httpx.Client.get", return_value=mock_resp_404),
        pytest.raises(IntigritiNotFoundError, match="no encontrado"),
    ):
        client.get_program_details("unknown-id")


def test_intigriti_mcp_server_protocol(tmp_path):
    scope_path = str(tmp_path / "scope.yaml")
    db_path = str(tmp_path / "pipeline.db")
    server = IntigritiMCPServer(
        client=IntigritiClient(mock_mode=True),
        scope_path=scope_path,
        db_path=db_path,
    )

    # 1. Initialize
    init_res = json.loads(server.dispatch(json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize"})))
    assert init_res["result"]["serverInfo"]["name"] == "bbpipeline-intigriti-mcp"

    # 2. Tools list
    list_res = json.loads(server.dispatch(json.dumps({"jsonrpc": "2.0", "id": 2, "method": "tools/list"})))
    tool_names = [t["name"] for t in list_res["result"]["tools"]]
    assert "intigriti_list_programs" in tool_names
    assert "intigriti_select_client" in tool_names
    assert "intigriti_get_active_client" in tool_names

    # 3. Call tool: intigriti_list_programs
    call_list = json.loads(server.dispatch(json.dumps({
        "jsonrpc": "2.0",
        "id": 3,
        "method": "tools/call",
        "params": {"name": "intigriti_list_programs", "arguments": {"limit": 5}},
    })))
    assert call_list["result"]["isError"] is False
    data = json.loads(call_list["result"]["content"][0]["text"])
    assert data["status"] == "success"
    assert data["count"] >= 2

    # 4. Call tool: intigriti_select_client
    call_select = json.loads(server.dispatch(json.dumps({
        "jsonrpc": "2.0",
        "id": 4,
        "method": "tools/call",
        "params": {
            "name": "intigriti_select_client",
            "arguments": {"program_id": "intigriti-sandbox", "scope_path": scope_path},
        },
    })))
    assert call_select["result"]["isError"] is False
    select_data = json.loads(call_select["result"]["content"][0]["text"])
    assert select_data["status"] == "success"
    assert select_data["program_id"] == "intigriti-sandbox"

    # 5. Call tool: intigriti_get_active_client
    call_active = json.loads(server.dispatch(json.dumps({
        "jsonrpc": "2.0",
        "id": 5,
        "method": "tools/call",
        "params": {"name": "intigriti_get_active_client", "arguments": {"scope_path": scope_path}},
    })))
    active_data = json.loads(call_active["result"]["content"][0]["text"])
    assert active_data["status"] == "active"
    assert active_data["id"] == "intigriti-sandbox"


def test_cli_intigriti_commands(tmp_path):
    scope_path = str(tmp_path / "cli_scope.yaml")
    db_path = str(tmp_path / "cli_pipeline.db")
    cred_file = str(tmp_path / "credentials.json")

    # 1. Login vía CLI hacia archivo aislado
    res_login = run_cli("intigriti", "login", "--token", "test-token-from-cli", "--credentials-path", cred_file)
    assert res_login.returncode == 0
    assert "guardado de forma segura" in res_login.stdout

    # 2. List vía CLI
    res_list = run_cli("intigriti", "list", "--mock")
    assert res_list.returncode == 0
    assert "Programas disponibles en Intigriti" in res_list.stdout

    # 3. Info vía CLI
    res_info = run_cli("intigriti", "info", "intigriti-sandbox", "--mock")
    assert res_info.returncode == 0
    assert "Intigriti Researcher Sandbox" in res_info.stdout

    # 4. Select vía CLI
    res_sel = run_cli(
        "intigriti",
        "select",
        "intigriti-sandbox",
        "--scope-path",
        scope_path,
        "--db-path",
        db_path,
        "--mock",
    )
    assert res_sel.returncode == 0
    assert "seleccionado y sincronizado con éxito" in res_sel.stdout
