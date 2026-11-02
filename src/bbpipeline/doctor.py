"""Módulo de diagnóstico de dependencias y herramientas externas del pipeline."""

from __future__ import annotations

import shutil
import subprocess
from collections.abc import Iterable
from dataclasses import dataclass
from importlib import metadata

DEFAULT_REQUIRED_TOOLS: tuple[str, ...] = (
    "nuclei",
    "subfinder",
    "amass",
    "ffuf",
    "httpx",
    "nmap",
)

DEFAULT_REQUIRED_PYTHON_PACKAGES: tuple[str, ...] = (
    "pyyaml",
    "pydantic",
    "httpx",
)

# Marcadores de identidad que los binarios de seguridad deben presentar en --version.
TOOL_VERSION_MARKERS: dict[str, str] = {
    "nuclei": "nuclei",
    "subfinder": "subfinder",
    "amass": "amass",
    "ffuf": "ffuf",
    "httpx": "projectdiscovery",
    "nmap": "nmap",
}


@dataclass(frozen=True)
class DoctorCheck:
    name: str
    status: str  # "ok" | "missing" | "error"
    detail: str


@dataclass(frozen=True)
class DoctorReport:
    checks: tuple[DoctorCheck, ...]

    @property
    def healthy(self) -> bool:
        return all(check.status == "ok" for check in self.checks)

    def missing(self) -> list[str]:
        return [check.name for check in self.checks if check.status != "ok"]


def check_tool_available(
    tool_name: str,
    version_args: tuple[str, ...] = ("--version",),
    marker: str | None = None,
) -> DoctorCheck:
    binary = shutil.which(tool_name)
    if not binary:
        return DoctorCheck(name=tool_name, status="missing", detail=f"Binario '{tool_name}' no encontrado en PATH")

    try:
        proc = subprocess.run([binary, *version_args], check=False, capture_output=True, text=True, timeout=30)
    except (OSError, subprocess.SubprocessError):
        return DoctorCheck(
            name=tool_name,
            status="missing",
            detail=f"Binario '{tool_name}' no pudo ejecutarse para verificar la version",
        )

    output = f"{(proc.stdout or '').strip()} {(proc.stderr or '').strip()}".strip()
    if proc.returncode != 0 or not output:
        return DoctorCheck(
            name=tool_name,
            status="missing",
            detail=f"Binario '{tool_name}' no respondio correctamente a {version_args[0]}",
        )

    if marker is not None and marker.lower() not in output.lower():
        return DoctorCheck(
            name=tool_name,
            status="missing",
            detail=f"Binario '{tool_name}' no es la herramienta de seguridad esperada (respuesta: {output[:60]})",
        )

    return DoctorCheck(name=tool_name, status="ok", detail=f"Disponible en {binary}")


def check_python_package(package: str) -> DoctorCheck:
    try:
        version = metadata.version(package)
    except metadata.PackageNotFoundError:
        return DoctorCheck(name=package, status="missing", detail="Paquete Python no instalado")
    return DoctorCheck(name=package, status="ok", detail=f"Instalado (v{version})")


def run_checks(
    tools: Iterable[str] | None = None,
    packages: Iterable[str] | None = None,
) -> DoctorReport:
    """Ejecuta el diagnostico completo de entorno del pipeline."""
    resolved_tools = list(tools) if tools is not None else list(DEFAULT_REQUIRED_TOOLS)
    resolved_packages = list(packages) if packages is not None else list(DEFAULT_REQUIRED_PYTHON_PACKAGES)

    checks = [check_tool_available(tool, marker=TOOL_VERSION_MARKERS.get(tool)) for tool in resolved_tools]
    checks.extend(check_python_package(package) for package in resolved_packages)
    return DoctorReport(checks=tuple(checks))
