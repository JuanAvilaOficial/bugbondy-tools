import pytest
from pydantic import ValidationError

from bbpipeline.contracts import Finding, Severity, StageMetadata, StagePayload


def test_stage_payload_accepts_valid_payload():
    payload = StagePayload(
        program_id="example-program",
        stage="01-recon",
        action="subfinder.run",
        target="api.example.com",
    )

    assert payload.program_id == "example-program"
    assert payload.stage == "01-recon"
    assert payload.action == "subfinder.run"
    assert payload.target == "api.example.com"


def test_stage_payload_rejects_missing_required_fields():
    with pytest.raises(ValidationError):
        StagePayload(stage="01-recon", action="subfinder.run")


def test_stage_metadata_defaults():
    metadata = StageMetadata()

    assert metadata.stage == "00-scope-manager"
    assert metadata.actor == "agent"
    assert metadata.correlation_id is None


def test_stage_payload_output_envelope_defaults():
    payload = StagePayload(program_id="example-program", stage="03-vuln-scan", action="nuclei.scan")

    assert payload.status == "pending"
    assert payload.findings == []
    assert payload.next_stage is None
    assert payload.requires_human_approval is False
    assert payload.output is None


def test_finding_accepts_valid_severity():
    finding = Finding(program_id="example-program", title="Stored XSS", severity=Severity.HIGH)

    assert finding.severity is Severity.HIGH
    assert finding.is_high_or_critical() is True


def test_finding_rejects_unknown_severity():
    with pytest.raises(ValidationError):
        Finding(program_id="example-program", title="Stored XSS", severity="extreme")
