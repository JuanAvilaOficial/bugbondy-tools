import pytest

from bbpipeline.templates import TemplateAllowlist, TemplateNotAllowedError


def test_default_allowlist_allows_known_cve_templates():
    allowlist = TemplateAllowlist()

    assert allowlist.is_allowed("cves/2021/CVE-2021-44228.yaml") is True
    assert allowlist.is_allowed("technologies/apache/log4j_cve_2021_44228.yaml") is True


def test_default_allowlist_denies_unknown_templates():
    allowlist = TemplateAllowlist()

    assert allowlist.is_allowed("rce/unknown/SomeExploit.yaml") is False
    assert allowlist.is_allowed("") is False


def test_validate_template_raises_when_not_allowed():
    allowlist = TemplateAllowlist()

    # Plantilla conocida: no debe lanzar
    allowlist.validate_template("cves/2021/CVE-2021-44228.yaml")

    # Plantilla no autorizada: debe lanzar
    with pytest.raises(TemplateNotAllowedError):
        allowlist.validate_template("rce/evil/ReverseShell.yaml")


def test_custom_allowlist_overrides_defaults():
    allowlist = TemplateAllowlist(allowed_templates=["cves/", "fuzz/"])

    assert allowlist.is_allowed("cves/2021/CVE-2021-44228.yaml") is True
    assert allowlist.is_allowed("fuzz/baited.yaml") is True
    assert allowlist.is_allowed("technologies/whatever.yaml") is False


def test_empty_allowlist_fails_closed():
    allowlist = TemplateAllowlist(allowed_templates=[])

    assert allowlist.is_allowed("cves/2021/CVE-2021-44228.yaml") is False
    with pytest.raises(TemplateNotAllowedError):
        allowlist.validate_template("cves/2021/CVE-2021-44228.yaml")


def test_blocked_destructive_template_prefixes():
    allowlist = TemplateAllowlist(allowed_templates=["cves/", "fuzz/"])

    assert allowlist.is_allowed("cves/2021/CVE-2021-44228.yaml") is True
    assert allowlist.is_allowed("dos/2016/crazy_dos.yaml") is False
    assert allowlist.is_allowed("ddos/2024/attack.yaml") is False
