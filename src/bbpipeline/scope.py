"""Módulo de control de alcance (Scope Guard).

Asegura que ninguna petición o herramienta de red interactúe con activos fuera de alcance.
Implementa política Fail-Closed: si no está explícitamente permitido, o ante cualquier duda, se rechaza.
"""

from __future__ import annotations

import ipaddress
import re
import socket
from pathlib import Path
from urllib.parse import urlparse

import yaml
from pydantic import BaseModel, Field


class ScopeViolationError(Exception):
    """Lanzada cuando un target viola las reglas de alcance del programa."""


class TargetRule(BaseModel):
    target: str
    type: str  # wildcard, domain, url, cidr, ip
    eligible_for_bounty: bool = True
    reason: str | None = None


class ScopeSection(BaseModel):
    targets: list[TargetRule] = Field(default_factory=list)
    vulnerability_types: list[str] = Field(default_factory=list)


class ProgramScope(BaseModel):
    id: str
    name: str
    platform: str
    policy_url: str | None = None
    policy_hash: str | None = None
    last_verified: str | None = None
    scope: dict[str, ScopeSection]

    @property
    def in_scope_targets(self) -> list[TargetRule]:
        return self.scope.get("in_scope", ScopeSection()).targets

    @property
    def out_of_scope_targets(self) -> list[TargetRule]:
        return self.scope.get("out_of_scope", ScopeSection()).targets


class ScopeConfig(BaseModel):
    version: str
    programs: list[ProgramScope]


PRIVATE_AND_RESERVED_NETWORKS = [
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("169.254.0.0/16"),  # Link-local / Cloud metadata
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
]


class ScopeGuard:
    def __init__(self, config_path: str | Path | None = None, config: ScopeConfig | None = None):
        if config is not None:
            self.config = config
        elif config_path is not None:
            self.config = self.load_config(config_path)
        else:
            default_path = Path("config/scope.yaml")
            if default_path.exists():
                self.config = self.load_config(default_path)
            else:
                raise ValueError("Se debe proporcionar config_path o config.")

        self.programs_by_id = {p.id: p for p in self.config.programs}

    @classmethod
    def load_config(cls, path: str | Path) -> ScopeConfig:
        path = Path(path)
        if not path.exists():
            raise FileNotFoundError(f"Archivo de configuración de scope no encontrado: {path}")

        with open(path, "r", encoding="utf-8") as f:
            raw_data = yaml.safe_load(f)

        return ScopeConfig.model_validate(raw_data)

    def get_program(self, program_id: str | None = None) -> ProgramScope:
        if program_id is None:
            if len(self.programs_by_id) == 1:
                return next(iter(self.programs_by_id.values()))
            raise ValueError("Múltiples programas disponibles; debe especificar program_id.")

        if program_id not in self.programs_by_id:
            raise KeyError(f"Programa '{program_id}' no encontrado en la configuración.")

        return self.programs_by_id[program_id]

    def _extract_host_and_url(self, target: str) -> tuple[str, str | None]:
        target = target.strip()
        if not target:
            raise ValueError("El target no puede estar vacío.")

        # Si parece una URL con esquema
        if target.startswith(("http://", "https://")):
            parsed = urlparse(target)
            return parsed.hostname or "", target

        # Si tiene barras pero no esquema
        if "/" in target and not re.match(r"^\d{1,3}(\.\d{1,3}){3}/\d{1,2}$", target):
            parsed = urlparse(f"https://{target}")
            return parsed.hostname or "", f"https://{target}"

        # Puede ser un host:puerto o un host plano o CIDR
        host = target.split(":")[0]
        return host.lower(), None

    def _is_ip(self, val: str) -> bool:
        try:
            ipaddress.ip_address(val)
            return True
        except ValueError:
            return False

    def _match_cidr_rule(self, ip_str: str, cidr_rule: str) -> bool:
        try:
            ip = ipaddress.ip_address(ip_str)
            network = ipaddress.ip_network(cidr_rule, strict=False)
            return ip in network
        except ValueError:
            return False

    def _match_domain_or_wildcard(self, hostname: str, rule_target: str) -> bool:
        hostname = hostname.lower().strip()
        rule = rule_target.lower().strip()

        if rule.startswith("*."):
            base_domain = rule[2:]
            # Coincide con subdominios (*.example.com -> a.example.com, b.a.example.com)
            # o con el dominio apex (example.com)
            return hostname == base_domain or hostname.endswith(f".{base_domain}")

        return hostname == rule

    def _matches_target_rule(self, host: str, full_url: str | None, rule: TargetRule) -> bool:
        rule_type = rule.type.lower()
        rule_target = rule.target.strip()

        if rule_type == "url":
            if full_url is None:
                # Comprobar contra host de la regla
                rule_parsed = urlparse(rule_target)
                return host == (rule_parsed.hostname or "").lower()
            return full_url.startswith(rule_target)

        if rule_type == "cidr":
            if self._is_ip(host):
                return self._match_cidr_rule(host, rule_target)
            return False

        if rule_type == "ip":
            return host == rule_target.lower()

        if rule_type in ("wildcard", "domain"):
            return self._match_domain_or_wildcard(host, rule_target)

        # Fallback de coincidencia general
        if rule_target.startswith("*."):
            return self._match_domain_or_wildcard(host, rule_target)

        return host == rule_target.lower()

    def check_dns(
        self,
        hostname: str,
        program: ProgramScope,
        allow_private_ips: bool = False,
    ) -> list[str]:
        """Resuelve el hostname y verifica que las IPs no caigan en rangos prohibidos o out-of-scope."""
        try:
            addr_info = socket.getaddrinfo(hostname, None)
            resolved_ips = list({info[4][0] for info in addr_info})
        except socket.gaierror as e:
            raise ScopeViolationError(f"Fallo al resolver DNS para '{hostname}': {e}") from e

        if not resolved_ips:
            raise ScopeViolationError(f"No se pudieron resolver direcciones IP para '{hostname}'.")

        for ip_str in resolved_ips:
            try:
                ip_obj = ipaddress.ip_address(ip_str)
            except ValueError:
                continue

            # Verificar contra redes privadas/reservadas si no están expresamente permitidas
            if not allow_private_ips:
                for reserved in PRIVATE_AND_RESERVED_NETWORKS:
                    if ip_obj in reserved:
                        raise ScopeViolationError(
                            f"Resolución DNS para '{hostname}' dio IP privada/reservada no permitida: {ip_str} (red {reserved})"
                        )

            # Verificar contra out_of_scope CIDRs/IPs
            for oos in program.out_of_scope_targets:
                if oos.type.lower() in ("cidr", "ip") and self._match_cidr_rule(ip_str, oos.target):
                    raise ScopeViolationError(
                        f"Resolución DNS para '{hostname}' resolvió a IP fuera de alcance ({ip_str} en {oos.target})"
                    )

        return resolved_ips

    def is_in_scope(
        self,
        target: str,
        program_id: str | None = None,
        resolve_dns: bool = False,
        allow_private_ips: bool = False,
    ) -> bool:
        """Verifica si un target está en alcance de manera segura (fail-closed)."""
        try:
            self.validate_target(
                target=target,
                program_id=program_id,
                resolve_dns=resolve_dns,
                allow_private_ips=allow_private_ips,
            )
            return True
        except (ScopeViolationError, ValueError, KeyError):
            return False

    def validate_target(
        self,
        target: str,
        program_id: str | None = None,
        resolve_dns: bool = False,
        allow_private_ips: bool = False,
    ) -> None:
        """Valida que el target esté en alcance. Lanza ScopeViolationError si no lo está."""
        program = self.get_program(program_id)
        host, full_url = self._extract_host_and_url(target)

        # 1. Regla Fail-Closed: Revisar OUT OF SCOPE primero
        for oos_rule in program.out_of_scope_targets:
            if self._matches_target_rule(host, full_url, oos_rule):
                reason = f" ({oos_rule.reason})" if oos_rule.reason else ""
                raise ScopeViolationError(
                    f"Target '{target}' está explícitamente fuera de alcance por regla: {oos_rule.target}{reason}"
                )

        # 2. Revisar IN SCOPE
        matched_in_scope = False
        for in_rule in program.in_scope_targets:
            if self._matches_target_rule(host, full_url, in_rule):
                matched_in_scope = True
                break

        if not matched_in_scope:
            raise ScopeViolationError(
                f"Target '{target}' no coincide con ninguna regla in_scope del programa '{program.id}'"
            )

        # 3. Comprobación de DNS y SSRF (si aplica y host no es ya una IP)
        if resolve_dns and not self._is_ip(host):
            self.check_dns(host, program, allow_private_ips=allow_private_ips)

    def validate_redirect(
        self,
        origin_url: str,
        redirect_url: str,
        program_id: str | None = None,
        resolve_dns: bool = False,
    ) -> None:
        """Valida que la URL de redirección no dirija fuera del scope."""
        self.validate_target(redirect_url, program_id=program_id, resolve_dns=resolve_dns)
