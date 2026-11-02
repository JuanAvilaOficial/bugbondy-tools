import importlib.util
from pathlib import Path
from types import SimpleNamespace

import pytest

from bbpipeline.contracts import StagePayload
from bbpipeline.scope import ScopeViolationError
from bbpipeline.templates import TemplateAllowlist, TemplateNotAllowedError

MODULE_PATH = (
    Path(__file__).parent.parent / "skills" / "03-vuln-scan" / "mcp_nuclei.py"
)


def load_module():
    spec = importlib.util.spec_from_file_location("mcp_nuclei_under_test", MODULE_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def make_payload(templates: list[str], target: str = "api.example.com") -> StagePayload:
    return StagePayload(
        program_id="example-program",
        stage="03-vuln-scan",
        action="nuclei.scan",
        target=target,
        parameters={"templates": templates},
    )


def test_execute_scan_rejects_disallowed_template():
    module = load_module()
    module._ALLOWLIST = TemplateAllowlist(allowed_templates=["cves/"])

    with pytest.raises(TemplateNotAllowedError):
        module.execute_scan(make_payload(["rce/evil/ReverseShell.yaml"]))


def test_execute_scan_rejects_empty_template_list():
    module = load_module()
    module._ALLOWLIST = TemplateAllowlist(allowed_templates=["cves/"])

    with pytest.raises(ValueError):
        module.execute_scan(make_payload([]))


def test_execute_scan_rejects_out_of_scope_target():
    module = load_module()
    module._ALLOWLIST = TemplateAllowlist(allowed_templates=["cves/"])
    module._AUDIT_LOGGER = SimpleNamespace(log=lambda **kwargs: None)

    with pytest.raises(ScopeViolationError):
        module.execute_scan(make_payload(["cves/2021/CVE-2021-44228.yaml"], target="support.example.com"))


def test_execute_scan_happy_path_with_mocked_run_tool():
    module = load_module()
    module._ALLOWLIST = TemplateAllowlist(allowed_templates=["cves/", "technologies/"])
    module._AUDIT_LOGGER = SimpleNamespace(log=lambda **kwargs: None)
    fake_output = {"command": ["nuclei", "-u", "api.example.com", "-t", "cves/2021/CVE-2021-44228.yaml"], "returncode": 0, "stdout": "", "stderr": ""}

    output = module.execute_scan(
        make_payload(["cves/2021/CVE-2021-44228.yaml"]),
        run_tool_fn=lambda command, timeout=120: fake_output,
    )

    assert output == fake_output
