"""Modelo de contrato JSON para el intercambio de datos entre stages y skills.

Garantiza que cualquier skill o stage que produzca o consuma artefactos JSON
valida la estructura de entrada/salida antes de pasar al siguiente paso,
evitando errores de parseo y respuestas fuera de contrato.
"""

from __future__ import annotations

from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class StageMetadata(BaseModel):
    stage: str = Field(default="00-scope-manager", description="Etapa del pipeline: 00 .. 07")
    actor: str = Field(default="agent", description="Agente o humano que ejecuta la acción")
    correlation_id: str | None = Field(default=None, description="ID de correlación de trazabilidad")


class Finding(BaseModel):
    """Contrato de hallazgo que fluye entre fases (triage -> verify -> report)."""

    model_config = ConfigDict(extra="forbid")

    program_id: str = Field(..., description="Programa al que pertenece el hallazgo")
    title: str = Field(..., description="Título técnico del hallazgo")
    severity: Severity = Field(..., description="Severidad: info | low | medium | high | critical")
    description: str | None = Field(default=None)
    proof_of_concept: str | None = Field(default=None)
    cvss: float | None = Field(default=None, description="CVSS 0.0 - 10.0")
    cve: str | None = Field(default=None, description="CVE asociado (opcional)")
    asset_id: int | None = Field(default=None, description="ID del activo asociado")
    status: str = Field(default="discovered", description="Estado inicial del hallazgo")

    def is_high_or_critical(self) -> bool:
        """Indica si el hallazgo requiere verificación prioritaria humana."""
        return self.severity in (Severity.HIGH, Severity.CRITICAL)


class StagePayload(BaseModel):
    """Contrato de entrada/salida entre stages y skills."""

    model_config = ConfigDict(extra="forbid")

    pipeline_id: str = Field(default="bugbounty-pipeline")
    program_id: str = Field(..., description="ID del programa objetivo (ej. example-program)")
    stage: str = Field(..., description="Etapa del pipeline (ej. 01-recon)")
    action: str = Field(..., description="Acción planificada (ej. subfinder.run, nuclei.scan)")
    target: str | None = Field(default=None, description="Activo objetivo (opcional)")
    parameters: dict[str, Any] = Field(default_factory=dict, description="Parámetros operacionales")
    metadata: StageMetadata = Field(default_factory=StageMetadata)
    status: str = Field(default="pending", description="Estado de la etapa: pending | completed | failed")
    findings: list[Finding] = Field(default_factory=list, description="Hallazgos detectados en la salida")
    next_stage: str | None = Field(default=None, description="Etapa sugerida para el siguiente paso")
    requires_human_approval: bool = Field(default=False, description="Indica si la siguiente etapa requiere gate humano")
    output: dict[str, Any] | None = Field(default=None, description="Salida cruda de la herramienta")
