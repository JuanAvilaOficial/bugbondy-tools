
from bbpipeline.doctor import check_python_package, check_tool_available, run_checks


class FakeCompleted:
    def __init__(self, returncode: int = 0, stdout: str = "", stderr: str = "") -> None:
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


def test_check_tool_available_found(monkeypatch):
    monkeypatch.setattr("bbpipeline.doctor.shutil.which", lambda name: f"/usr/bin/{name}")
    monkeypatch.setattr("bbpipeline.doctor.subprocess.run", lambda *args, **kwargs: FakeCompleted(stdout="nuclei version 2.0.0"))
    check = check_tool_available("nuclei")
    assert check.status == "ok"
    assert check.name == "nuclei"


def test_check_tool_available_missing(monkeypatch):
    monkeypatch.setattr("bbpipeline.doctor.shutil.which", lambda name: None)
    check = check_tool_available("nuclei")
    assert check.status == "missing"
    assert check.name == "nuclei"


def test_check_tool_available_rejects_wrong_binary(monkeypatch):
    # httpx debe ser el binario de ProjectDiscovery (Go); un binario que no
    # contenga el marcador se considera no confiable para el pipeline.
    monkeypatch.setattr("bbpipeline.doctor.shutil.which", lambda name: "/usr/bin/httpx")
    monkeypatch.setattr(
        "bbpipeline.doctor.subprocess.run",
        lambda *args, **kwargs: FakeCompleted(stdout="httpx version 0.1.0 (python client)"),
    )

    check = check_tool_available("httpx", marker="projectdiscovery")
    assert check.status == "missing"


def test_check_python_package_installed(monkeypatch):
    monkeypatch.setattr("bbpipeline.doctor.metadata.version", lambda pkg: "1.2.3")
    check = check_python_package("pydantic")
    assert check.status == "ok"
    assert check.name == "pydantic"


def test_check_python_package_not_installed(monkeypatch):
    from importlib import metadata

    def _not_found(pkg: str):
        raise metadata.PackageNotFoundError(pkg)

    monkeypatch.setattr("bbpipeline.doctor.metadata.version", _not_found)
    check = check_python_package("pydantic")
    assert check.status == "missing"


def test_run_checks_healthy_when_all_ok(monkeypatch):
    monkeypatch.setattr("bbpipeline.doctor.shutil.which", lambda name: f"/usr/bin/{name}")
    monkeypatch.setattr("bbpipeline.doctor.subprocess.run", lambda *args, **kwargs: FakeCompleted(stdout="nuclei version 2.0.0"))

    report = run_checks(tools=["nuclei"], packages=["pydantic"])

    assert report.healthy is True
    assert report.missing() == []


def test_run_checks_reports_missing_tools(monkeypatch):
    monkeypatch.setattr("bbpipeline.doctor.shutil.which", lambda name: None)

    report = run_checks(tools=["nuclei", "ffuf"], packages=[])

    assert report.healthy is False
    assert report.missing() == ["nuclei", "ffuf"]
