from unittest.mock import patch

import pytest

from bbpipeline.scope import ScopeGuard, ScopeViolationError


@pytest.fixture
def scope_guard():
    return ScopeGuard("config/scope.yaml")


def test_wildcard_matching(scope_guard):
    # En scope según config/scope.yaml (*.example.com)
    assert scope_guard.is_in_scope("foo.example.com") is True
    assert scope_guard.is_in_scope("api.sub.example.com") is True
    assert scope_guard.is_in_scope("example.com") is True

    # Fuera de scope general
    assert scope_guard.is_in_scope("notexample.com") is False
    assert scope_guard.is_in_scope("example.org") is False


def test_out_of_scope_override(scope_guard):
    # support.example.com y payments.example.com están en out_of_scope explícito
    assert scope_guard.is_in_scope("support.example.com") is False
    assert scope_guard.is_in_scope("payments.example.com") is False

    with pytest.raises(ScopeViolationError, match="fuera de alcance"):
        scope_guard.validate_target("support.example.com")


def test_cidr_matching(scope_guard):
    # 192.0.2.0/24 está in_scope
    assert scope_guard.is_in_scope("192.0.2.1") is True
    assert scope_guard.is_in_scope("192.0.2.254") is True

    # Fuera de la CIDR
    assert scope_guard.is_in_scope("192.0.3.1") is False
    assert scope_guard.is_in_scope("8.8.8.8") is False


def test_url_matching(scope_guard):
    # https://api.example.com está in_scope
    assert scope_guard.is_in_scope("https://api.example.com/v1/users") is True
    assert scope_guard.is_in_scope("http://unauthorized.com/test") is False


def test_redirect_validation(scope_guard):
    # Redirección a target válido
    scope_guard.validate_redirect(
        origin_url="https://api.example.com/auth",
        redirect_url="https://login.example.com/oauth",
    )

    # Redirección fuera de scope
    with pytest.raises(ScopeViolationError):
        scope_guard.validate_redirect(
            origin_url="https://api.example.com/auth",
            redirect_url="https://evil-phishing.com/callback",
        )

    # Redirección a subdominio out_of_scope
    with pytest.raises(ScopeViolationError):
        scope_guard.validate_redirect(
            origin_url="https://api.example.com/auth",
            redirect_url="https://support.example.com/login",
        )


def test_dns_resolution_private_ip_blocking(scope_guard):
    # Mock de resolución DNS que retorna IP privada (127.0.0.1) -> Debe bloquearse (anti-SSRF)
    with patch("socket.getaddrinfo", return_value=[(None, None, None, None, ("127.0.0.1", 0))]), pytest.raises(
        ScopeViolationError, match="IP privada/reservada"
    ):
        scope_guard.validate_target("app.example.com", resolve_dns=True)

    # Mock de resolución DNS que retorna IP de metadatos de la nube (169.254.169.254)
    with patch("socket.getaddrinfo", return_value=[(None, None, None, None, ("169.254.169.254", 0))]), pytest.raises(
        ScopeViolationError, match="IP privada/reservada"
    ):
        scope_guard.validate_target("app.example.com", resolve_dns=True)


def test_fail_closed_on_empty_or_malformed(scope_guard):
    with pytest.raises(ValueError):
        scope_guard.validate_target("")

    with pytest.raises(ValueError):
        scope_guard.validate_target("   ")
