"""Módulo de integración con la Researcher API de Intigriti.

Provee autenticación segura, consulta de programas disponibles,
descarga de directivas de alcance (in-scope y out-of-scope),
extracción de requisitos de auditoría/cabeceras (User-Agent, headers obligatorios)
y sincronización en config/scope.yaml y state/pipeline.db.
"""

from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import httpx
import yaml

from bbpipeline.audit import AuditLogger
from bbpipeline.db import Database
from bbpipeline.scope import ProgramScope, ScopeConfig, ScopeSection, TargetRule

INTIGRITI_BASE_URL = "https://api.intigriti.com/external/researcher/v1"
CREDENTIALS_FILE = Path.home() / ".config" / "bbpipeline" / "credentials.json"


class IntigritiAPIError(Exception):
    """Error general devuelto por la API de Intigriti o fallo de comunicación."""


class IntigritiAuthError(IntigritiAPIError):
    """Error de autenticación o token inválido en Intigriti."""


class IntigritiNotFoundError(IntigritiAPIError):
    """Programa o recurso no encontrado en Intigriti."""


# Datos simulados para modo pruebas / desarrollo offline
MOCK_PROGRAMS: list[dict[str, Any]] = [
    {
        "id": "prog-sandbox-01",
        "handle": "intigriti-sandbox",
        "name": "Intigriti Researcher Sandbox",
        "following": True,
        "confidentialityLevel": {"id": 1, "value": "Public"},
        "status": {"id": 1, "value": "Open"},
        "type": {"id": 1, "value": "BugBounty"},
        "minBounty": {"value": 50, "currency": "EUR"},
        "maxBounty": {"value": 2500, "currency": "EUR"},
        "industry": "Cybersecurity",
        "webLinks": {"details": "https://app.intigriti.com/programs/sandbox"},
    },
    {
        "id": "prog-acme-02",
        "handle": "acme-corp",
        "name": "Acme Global Bug Bounty",
        "following": False,
        "confidentialityLevel": {"id": 2, "value": "Private"},
        "status": {"id": 1, "value": "Open"},
        "type": {"id": 1, "value": "BugBounty"},
        "minBounty": {"value": 100, "currency": "EUR"},
        "maxBounty": {"value": 6000, "currency": "EUR"},
        "industry": "Fintech",
        "webLinks": {"details": "https://app.intigriti.com/programs/acme-corp"},
    },
    {
        "id": "prog-wl-03",
        "handle": "wirelesslogic",
        "name": "Wireless Logic Bug Bounty",
        "following": True,
        "confidentialityLevel": {"id": 1, "value": "Public"},
        "status": {"id": 1, "value": "Open"},
        "type": {"id": 1, "value": "BugBounty"},
        "minBounty": {"value": 150, "currency": "EUR"},
        "maxBounty": {"value": 5000, "currency": "EUR"},
        "industry": "IoT / Telecom",
        "webLinks": {"details": "https://app.intigriti.com/researcher/programs/wl/wirelesslogic/preview/detail"},
    },
]

MOCK_PROGRAM_DETAILS: dict[str, dict[str, Any]] = {
    "prog-sandbox-01": {
        "id": "prog-sandbox-01",
        "handle": "intigriti-sandbox",
        "name": "Intigriti Researcher Sandbox",
        "confidentialityLevel": {"id": 1, "value": "Public"},
        "status": {"id": 1, "value": "Open"},
        "type": {"id": 1, "value": "BugBounty"},
        "domains": {
            "id": "ver-dom-01",
            "createdAt": 1700000000,
            "content": [
                {
                    "id": "dom-s1",
                    "type": {"id": 1, "value": "Url"},
                    "endpoint": "*.sandbox.intigriti.net",
                    "tier": {"id": 1, "value": "Tier 1"},
                    "description": "Sandbox subdomains wildcard",
                },
                {
                    "id": "dom-s2",
                    "type": {"id": 1, "value": "Url"},
                    "endpoint": "https://api.sandbox.intigriti.net",
                    "tier": {"id": 1, "value": "Tier 1"},
                    "description": "API REST endpoint",
                },
                {
                    "id": "dom-s3",
                    "type": {"id": 1, "value": "Url"},
                    "endpoint": "admin.sandbox.intigriti.net",
                    "tier": {"id": 5, "value": "Out of scope"},
                    "description": "Admin panel strictly excluded",
                },
            ],
        },
        "rulesOfEngagement": {
            "id": "ver-roe-01",
            "createdAt": 1700000000,
            "content": {
                "description": "Follow Safe Harbor rules. No aggressive DoS.",
                "testingRequirements": {
                    "intigritiMe": True,
                    "automatedTooling": 1,
                    "userAgent": "Intigriti-Researcher-Agent/1.0",
                    "requestHeader": "X-BugBounty-Hacker: researcher",
                },
                "safeHarbour": True,
            },
        },
    },
    "prog-acme-02": {
        "id": "prog-acme-02",
        "handle": "acme-corp",
        "name": "Acme Global Bug Bounty",
        "confidentialityLevel": {"id": 2, "value": "Private"},
        "status": {"id": 1, "value": "Open"},
        "type": {"id": 1, "value": "BugBounty"},
        "domains": {
            "id": "ver-dom-02",
            "createdAt": 1700000000,
            "content": [
                {
                    "id": "dom-a1",
                    "type": {"id": 1, "value": "Url"},
                    "endpoint": "*.acme.com",
                    "tier": {"id": 1, "value": "Tier 1"},
                    "description": "Main domain wildcard",
                },
                {
                    "id": "dom-a2",
                    "type": {"id": 1, "value": "Url"},
                    "endpoint": "careers.acme.com",
                    "tier": {"id": 5, "value": "Out of scope"},
                    "description": "Third-party recruitment portal",
                },
            ],
        },
        "rulesOfEngagement": {
            "id": "ver-roe-02",
            "createdAt": 1700000000,
            "content": {
                "description": "Report all vulnerabilities with reproducible PoC.",
                "testingRequirements": {
                    "intigritiMe": True,
                    "automatedTooling": 1,
                    "userAgent": "Intigriti-Acme-Agent/1.0",
                    "requestHeader": "X-Intigriti-Acme: researcher",
                },
                "safeHarbour": True,
            },
        },
    },
    "prog-wl-03": {
        "id": "prog-wl-03",
        "handle": "wirelesslogic",
        "name": "Wireless Logic Bug Bounty",
        "confidentialityLevel": {"id": 1, "value": "Public"},
        "status": {"id": 1, "value": "Open"},
        "type": {"id": 1, "value": "BugBounty"},
        "webLinks": {"details": "https://app.intigriti.com/researcher/programs/wl/wirelesslogic/preview/detail"},
        "domains": {
            "id": "ver-dom-wl",
            "createdAt": 1700000000,
            "content": [
                {
                    "id": "dom-wl-1",
                    "type": {"id": 1, "value": "Url"},
                    "endpoint": "*.wirelesslogic.com",
                    "tier": {"id": 1, "value": "Tier 1"},
                    "description": "Main domain wildcard",
                },
                {
                    "id": "dom-wl-2",
                    "type": {"id": 1, "value": "Url"},
                    "endpoint": "blog.wirelesslogic.com",
                    "tier": {"id": 5, "value": "Out of scope"},
                    "description": "Marketing blog",
                },
            ],
        },
        "rulesOfEngagement": {
            "id": "ver-roe-wl",
            "createdAt": 1700000000,
            "content": {
                "description": "Safe Harbor enabled. Follow responsible disclosure.",
                "testingRequirements": {
                    "intigritiMe": True,
                    "automatedTooling": 1,
                    "userAgent": "Intigriti-WL-Researcher/1.0",
                    "requestHeader": "X-BugBounty-Hacker: researcher",
                },
                "safeHarbour": True,
            },
        },
    },
}


def get_stored_token() -> str | None:
    """Obtiene el token de Intigriti desde variables de entorno o archivo de credenciales."""
    env_token = os.environ.get("INTIGRITI_TOKEN")
    if env_token and env_token.strip():
        return env_token.strip()

    if CREDENTIALS_FILE.exists():
        try:
            with open(CREDENTIALS_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
                token = data.get("intigriti_token")
                if token and isinstance(token, str):
                    return token.strip()
        except (json.JSONDecodeError, OSError):
            pass

    return None


def save_token(token: str, path: Path | None = None) -> Path:
    """Guarda el token de Intigriti en el archivo de credenciales local con permisos seguros."""
    target_path = path or CREDENTIALS_FILE
    target_path.parent.mkdir(parents=True, exist_ok=True)
    payload = {"intigriti_token": token.strip()}
    with open(target_path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2)
    try:
        os.chmod(target_path, 0o600)
    except OSError:
        pass
    return target_path


class IntigritiClient:
    """Cliente oficial para la Researcher API v1 de Intigriti."""

    def __init__(
        self,
        token: str | None = None,
        base_url: str = INTIGRITI_BASE_URL,
        mock_mode: bool | None = None,
        timeout: float = 30.0,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout

        resolved_token = token or get_stored_token()
        self.token = resolved_token

        # Si se especifica mock_mode explícito o INTIGRITI_MOCK=1 o no hay token provisto, activar mock
        env_mock = os.environ.get("INTIGRITI_MOCK", "").lower() in ("1", "true", "yes")
        if mock_mode is not None:
            self.mock_mode = mock_mode
        elif env_mock or not self.token:
            self.mock_mode = True
        else:
            self.mock_mode = False

    def _get_headers(self) -> dict[str, str]:
        if not self.token and not self.mock_mode:
            raise IntigritiAuthError(
                "No se encontró INTIGRITI_TOKEN. Configure la variable de entorno "
                "o use 'bbp intigriti login' para suministrar credenciales válidas."
            )
        return {
            "Authorization": f"Bearer {self.token}",
            "Accept": "application/json",
            "User-Agent": "BugBountyPipeline-Intigriti/1.0",
        }

    def list_programs(
        self,
        limit: int = 50,
        offset: int = 0,
        status: str | None = None,
    ) -> list[dict[str, Any]]:
        """Obtiene la lista de programas accesibles por el investigador en Intigriti."""
        if self.mock_mode:
            results = list(MOCK_PROGRAMS)
            if status:
                results = [
                    p for p in results if str(p.get("status", {}).get("value", "")).lower() == status.lower()
                ]
            return results[offset : offset + limit]

        url = f"{self.base_url}/programs"
        params: dict[str, Any] = {"limit": limit, "offset": offset}
        if status:
            params["status"] = status

        try:
            with httpx.Client(timeout=self.timeout) as client:
                res = client.get(url, headers=self._get_headers(), params=params)
                if res.status_code == 401:
                    raise IntigritiAuthError("Token de Intigriti no válido o expirado (401 Unauthorized).")
                if res.status_code == 403:
                    raise IntigritiAuthError("Acceso no autorizado en Intigriti (403 Forbidden).")
                res.raise_for_status()
                data = res.json()
                return data.get("records", []) if isinstance(data, dict) else data
        except httpx.HTTPError as e:
            raise IntigritiAPIError(f"Error conectando con la API de Intigriti: {e}") from e

    @staticmethod
    def extract_program_candidate(raw_identifier: str) -> str:
        """Extrae el handle o identificador de un programa a partir de una URL o texto directo."""
        raw = raw_identifier.strip()
        if not raw.startswith(("http://", "https://")):
            return raw.strip("/")
        path = urlparse(raw).path.strip("/")
        parts = [p for p in path.split("/") if p]
        if "programs" in parts:
            idx = parts.index("programs")
            after = parts[idx + 1 :]
            clean_after = [p for p in after if p not in ("preview", "detail", "overview", "rules", "domains")]
            if clean_after:
                return clean_after[-1]
        return raw

    def resolve_program_id(self, program_identifier: str) -> str:
        """Resuelve una URL, handle o GUID al ID oficial del programa en Intigriti."""
        candidate = self.extract_program_candidate(program_identifier)

        # Si ya tiene formato de GUID/UUID, usar directamente
        if re.match(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", candidate, re.IGNORECASE):
            return candidate

        # En modo mock: buscar en MOCK_PROGRAM_DETAILS
        if self.mock_mode:
            for p_id, details in MOCK_PROGRAM_DETAILS.items():
                if candidate.lower() in (p_id.lower(), str(details.get("handle", "")).lower()):
                    return p_id
            return candidate

        # En modo real: consultar list_programs para resolver handle -> GUID
        try:
            programs = self.list_programs(limit=100)
            for p in programs:
                p_id = str(p.get("id", ""))
                p_handle = str(p.get("handle", ""))
                if candidate.lower() in (p_id.lower(), p_handle.lower()):
                    return p_id
            for p in programs:
                links = str(p.get("webLinks", {}))
                p_name = str(p.get("name", ""))
                if candidate.lower() in links.lower() or candidate.lower() in p_name.lower():
                    return str(p.get("id", ""))
        except Exception:  # noqa: BLE001, S110
            pass

        return candidate

    def get_program_details(self, program_id: str) -> dict[str, Any]:
        """Obtiene los detalles completos de un programa por su ID, handle o URL."""
        resolved_id = self.resolve_program_id(program_id)
        if self.mock_mode:
            # Buscar por id o por handle
            for p_id, details in MOCK_PROGRAM_DETAILS.items():
                if resolved_id in (p_id, details.get("handle")) or program_id in (p_id, details.get("handle")):
                    return details
            raise IntigritiNotFoundError(f"Programa '{program_id}' no encontrado en Intigriti (modo mock).")

        url = f"{self.base_url}/programs/{resolved_id}"
        try:
            with httpx.Client(timeout=self.timeout) as client:
                res = client.get(url, headers=self._get_headers())
                if res.status_code == 401:
                    raise IntigritiAuthError("Token de Intigriti no válido o expirado.")
                if res.status_code == 404:
                    raise IntigritiNotFoundError(f"Programa '{program_id}' (ID: {resolved_id}) no encontrado en Intigriti.")
                res.raise_for_status()
                return res.json()
        except httpx.HTTPError as e:
            raise IntigritiAPIError(f"Error obteniendo detalles del programa '{program_id}': {e}") from e

    def get_program_domains(self, program_id: str, version_id: str | None = None) -> list[dict[str, Any]]:
        """Obtiene los dominios declarados en el alcance del programa."""
        resolved_id = self.resolve_program_id(program_id)
        details = self.get_program_details(resolved_id)
        domains_data = details.get("domains")
        if isinstance(domains_data, dict) and "content" in domains_data:
            return domains_data.get("content", [])

        # Si viene solo el version_id de dominios
        target_version = version_id or (domains_data.get("id") if isinstance(domains_data, dict) else None)
        if not target_version or self.mock_mode:
            return []

        url = f"{self.base_url}/programs/{resolved_id}/domains/{target_version}"
        try:
            with httpx.Client(timeout=self.timeout) as client:
                res = client.get(url, headers=self._get_headers())
                res.raise_for_status()
                data = res.json()
                return data.get("content", []) if isinstance(data, dict) else data
        except httpx.HTTPError as e:
            raise IntigritiAPIError(f"Error obteniendo dominios de '{program_id}': {e}") from e

    def get_program_roe(self, program_id: str, version_id: str | None = None) -> dict[str, Any]:
        """Obtiene las reglas de compromiso y requisitos de testing."""
        resolved_id = self.resolve_program_id(program_id)
        details = self.get_program_details(resolved_id)
        roe_data = details.get("rulesOfEngagement")
        if isinstance(roe_data, dict) and "content" in roe_data:
            return roe_data.get("content", {})

        target_version = version_id or (roe_data.get("id") if isinstance(roe_data, dict) else None)
        if not target_version or self.mock_mode:
            return {}

        url = f"{self.base_url}/programs/{resolved_id}/rules-of-engagements/{target_version}"
        try:
            with httpx.Client(timeout=self.timeout) as client:
                res = client.get(url, headers=self._get_headers())
                res.raise_for_status()
                data = res.json()
                return data.get("content", {}) if isinstance(data, dict) else data
        except httpx.HTTPError as e:
            raise IntigritiAPIError(f"Error obteniendo reglas de compromiso de '{program_id}': {e}") from e

    @staticmethod
    def _classify_target(raw_endpoint: str) -> tuple[str, str]:
        """Clasifica un endpoint de Intigriti en tipo y valor normalizado."""
        endpoint = raw_endpoint.strip()
        if endpoint.startswith("*."):
            return endpoint, "wildcard"
        if "://" in endpoint:
            parsed = urlparse(endpoint)
            if parsed.scheme in ("http", "https"):
                return endpoint, "url"
        if "/" in endpoint and not endpoint.startswith("http"):
            # Probable CIDR
            return endpoint, "cidr"
        return endpoint, "domain"

    def build_program_scope(self, program_id: str) -> ProgramScope:
        """Construye un objeto ProgramScope validado a partir de los datos de Intigriti."""
        details = self.get_program_details(program_id)
        real_id = details.get("handle") or details.get("id") or program_id
        name = details.get("name") or real_id
        web_links = details.get("webLinks", {})
        policy_url = web_links.get("details") if isinstance(web_links, dict) else None

        raw_domains = self.get_program_domains(program_id)
        in_scope_rules: list[TargetRule] = []
        out_of_scope_rules: list[TargetRule] = []

        for item in raw_domains:
            endpoint = item.get("endpoint", "").strip()
            if not endpoint:
                continue

            target_val, target_type = self._classify_target(endpoint)
            tier_info = item.get("tier", {})
            tier_name = str(tier_info.get("value", "")).lower() if isinstance(tier_info, dict) else ""
            desc = item.get("description", "")

            # Clasificar si es out-of-scope
            is_out = "out of scope" in tier_name or "out of scope" in desc.lower()

            if is_out:
                out_of_scope_rules.append(
                    TargetRule(
                        target=target_val,
                        type=target_type,
                        eligible_for_bounty=False,
                        reason=desc or "Marcado explícitamente fuera de alcance en Intigriti",
                    )
                )
            else:
                out_of_scope_rules_check = any(r.target == target_val for r in out_of_scope_rules)
                if not out_of_scope_rules_check:
                    in_scope_rules.append(
                        TargetRule(
                            target=target_val,
                            type=target_type,
                            eligible_for_bounty=True,
                            reason=desc or "Objetivo autorizado en Intigriti",
                        )
                    )

        # Requisitos de testing (validados vía extract_testing_requirements al sincronizar)
        scope_dict = {
            "in_scope": ScopeSection(
                targets=in_scope_rules,
                vulnerability_types=["Web Vulnerabilities", "API Security", "Business Logic"],
            ),
            "out_of_scope": ScopeSection(
                targets=out_of_scope_rules,
                vulnerability_types=["Denial of Service (DoS)", "Social Engineering", "Spam"],
            ),
        }

        # Guardar metadatos en policy_url o razón si es necesario
        return ProgramScope(
            id=real_id,
            name=name,
            platform="intigriti",
            policy_url=policy_url,
            scope=scope_dict,
        )

    def extract_testing_requirements(self, program_id: str) -> dict[str, str]:
        """Extrae cabeceras y User-Agent obligatorios exigidos por el programa."""
        roe = self.get_program_roe(program_id)
        testing_reqs = roe.get("testingRequirements", {}) if isinstance(roe, dict) else {}
        headers: dict[str, str] = {}
        if isinstance(testing_reqs, dict):
            ua = testing_reqs.get("userAgent")
            req_header = testing_reqs.get("requestHeader")
            if ua:
                headers["User-Agent"] = str(ua).strip()
            if req_header:
                headers["Request-Header"] = str(req_header).strip()
        return headers

    def sync_program_to_pipeline(
        self,
        program_id: str,
        scope_path: str | Path = "config/scope.yaml",
        db_path: str | Path | None = "state/pipeline.db",
        rate_limits_path: str | Path | None = "config/rate-limits.yaml",
        audit_path: str | Path = "logs/audit.jsonl",
    ) -> ProgramScope:
        """Sincroniza formalmente el programa de Intigriti en el archivo de alcance, la base de datos y auditoría."""
        scope_obj = self.build_program_scope(program_id)
        scope_file = Path(scope_path)
        scope_file.parent.mkdir(parents=True, exist_ok=True)

        # 1. Actualizar config/scope.yaml
        if scope_file.exists():
            with open(scope_file, "r", encoding="utf-8") as f:
                raw_yaml = yaml.safe_load(f) or {}
            config = ScopeConfig.model_validate(raw_yaml)
            # Reemplazar o agregar el programa
            updated_programs = [p for p in config.programs if p.id != scope_obj.id]
            updated_programs.append(scope_obj)
            config.programs = updated_programs
        else:
            config = ScopeConfig(version="1.0", programs=[scope_obj])

        with open(scope_file, "w", encoding="utf-8") as f:
            yaml.safe_dump(config.model_dump(mode="python"), f, sort_keys=False, indent=2)

        # 2. Registrar activos en SQLite si la DB existe o se solicita
        if db_path:
            db_p = Path(db_path)
            if db_p.exists():
                db = Database(db_p)
                with db.get_connection() as conn:
                    for rule in scope_obj.in_scope_targets:
                        asset_type = rule.type if rule.type in ("domain", "ip", "url", "cidr") else "domain"
                        conn.execute(
                            """
                            INSERT INTO assets (program_id, asset_type, value, in_scope, metadata)
                            VALUES (?, ?, ?, 1, ?)
                            ON CONFLICT(value) DO UPDATE SET
                                program_id=excluded.program_id,
                                in_scope=1
                            """,
                            (scope_obj.id, asset_type, rule.target, json.dumps({"source": "intigriti"})),
                        )
                    for rule in scope_obj.out_of_scope_targets:
                        asset_type = rule.type if rule.type in ("domain", "ip", "url", "cidr") else "domain"
                        conn.execute(
                            """
                            INSERT INTO assets (program_id, asset_type, value, in_scope, metadata)
                            VALUES (?, ?, ?, 0, ?)
                            ON CONFLICT(value) DO UPDATE SET
                                program_id=excluded.program_id,
                                in_scope=0
                            """,
                            (scope_obj.id, asset_type, rule.target, json.dumps({"source": "intigriti", "reason": rule.reason})),
                        )

        # 3. Actualizar rate-limits si el archivo existe
        if rate_limits_path:
            rl_file = Path(rate_limits_path)
            if rl_file.exists():
                with open(rl_file, "r", encoding="utf-8") as f:
                    rl_data = yaml.safe_load(f) or {}

                programs_dict = rl_data.get("programs", {})
                reqs = self.extract_testing_requirements(program_id)
                prog_entry = programs_dict.get(scope_obj.id, {})
                prog_entry.setdefault("max_requests_per_second", 10)
                prog_entry.setdefault("concurrency", 3)
                if reqs.get("User-Agent"):
                    prog_entry["user_agent"] = reqs["User-Agent"]
                if reqs.get("Request-Header"):
                    prog_entry["custom_header"] = reqs["Request-Header"]

                programs_dict[scope_obj.id] = prog_entry
                rl_data["programs"] = programs_dict

                with open(rl_file, "w", encoding="utf-8") as f:
                    yaml.safe_dump(rl_data, f, sort_keys=False, indent=2)

        # 4. Registrar en log de auditoría
        logger = AuditLogger(audit_path)
        logger.log(
            stage="00-scope-manager",
            event="intigriti_client_selected",
            target=scope_obj.id,
            actor="operator_or_mcp",
            details={
                "program_name": scope_obj.name,
                "in_scope_count": len(scope_obj.in_scope_targets),
                "out_of_scope_count": len(scope_obj.out_of_scope_targets),
            },
        )

        return scope_obj
