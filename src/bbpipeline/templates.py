"""Módulo de control de plantillas para herramientas de escaneo externas (ej. Nuclei).

Implementa allowlist de templates con política Fail-Closed: si una plantilla no
está explícitamente permitida (o la allowlist está vacía), la ejecución del scan
debe abortarse.
"""

from __future__ import annotations

from pathlib import Path

import yaml


class TemplateNotAllowedError(Exception):
    """Lanzada cuando una plantilla de escaneo no está autorizada."""


DEFAULT_ALLOWED_TEMPLATE_PREFIXES: tuple[str, ...] = (
    "cves/",
    "cve/",
    "technologies/",
    "misconfiguration/",
    "default-logins/",
    "exposure/",
    "fuzz/",
    "auth/",
    "ssl/",
    "headers/",
    "secrets/",
    "cloud/",
)

# Prefijos de plantillas consideradas de riesgo destructivo (DoS) y siempre bloqueados.
DEFAULT_BLOCKED_TEMPLATE_PREFIXES: tuple[str, ...] = (
    "dos/",
    "ddos/",
)


class TemplateAllowlist:
    def __init__(
        self,
        allowed_templates: list[str] | None = None,
        config_path: str | Path | None = None,
    ) -> None:
        if config_path is not None:
            self.allowed_templates = list(self.load_config(config_path).allowed_templates)
        elif allowed_templates is not None:
            self.allowed_templates = list(allowed_templates)
        else:
            self.allowed_templates = list(DEFAULT_ALLOWED_TEMPLATE_PREFIXES)
        self.blocked_prefixes: tuple[str, ...] = DEFAULT_BLOCKED_TEMPLATE_PREFIXES

    @classmethod
    def load_config(cls, path: str | Path) -> TemplateAllowlist:
        resolved = Path(path)
        templates: list[str] = []
        if resolved.exists():
            with open(resolved, "r", encoding="utf-8") as f:
                raw = yaml.safe_load(f) or {}
            nuclei_conf = raw.get("nuclei") or {}
            templates = [str(t) for t in (nuclei_conf.get("allowed_templates") or [])]

        if not templates:
            templates = list(DEFAULT_ALLOWED_TEMPLATE_PREFIXES)
        return cls(allowed_templates=templates)

    @staticmethod
    def _normalize(value: str) -> str:
        normalized = str(value).strip().lower()
        while normalized.startswith("./"):
            normalized = normalized[2:]
        return normalized

    def is_allowed(self, template: str) -> bool:
        """Verifica si una plantilla está dentro de la allowlist (fail-closed)."""
        target = self._normalize(template)
        if not target:
            return False

        for prefix in self.blocked_prefixes:
            if target.startswith(prefix):
                return False

        for raw_entry in self.allowed_templates:
            pattern = self._normalize(str(raw_entry))
            if not pattern:
                continue

            if "*" in pattern:
                prefix = pattern.split("*", 1)[0].rstrip("/")
                if prefix and (target == prefix or target.startswith(f"{prefix}/")):
                    return True
            elif pattern.endswith("/"):
                if target.startswith(pattern):
                    return True
            elif target == pattern:
                return True

        return False

    def validate_template(self, template: str) -> None:
        """Valida una plantilla; lanza TemplateNotAllowedError si no está autorizada."""
        if not self.is_allowed(template):
            raise TemplateNotAllowedError(
                f"Plantilla '{template}' no está en la allowlist de plantillas del pipeline."
            )
