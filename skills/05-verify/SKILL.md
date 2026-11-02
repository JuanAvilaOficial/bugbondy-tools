---
name: 05-verify
description: Gate humano obligatorio para validar y confirmar vulnerabilidades antes del reporte.
---

# 05 - Verification (Gate Humano Obligatorio)

> [!CAUTION]
> **GATE HUMANO OBLIGATORIO:** Ningún hallazgo puede avanzar a la etapa de reporte (`06-report`) o envío (`07-submit-track`) sin la aprobación explícita y manual de un operador humano.

## Propósito
Confirmar manualmente la reproducibilidad del hallazgo, el impacto real en el negocio y la ausencia de efectos no deseados.

## Criterios del Gate
1. **Reproducibilidad:** El operador humano debe poder replicar el hallazgo siguiendo un PoC paso a paso.
2. **Impacto:** Demostración clara del riesgo de seguridad sin suposiciones teóricas.
3. **Validación de Scope:** Re-verificación manual de que el endpoint y la vulnerabilidad son válidos según las reglas actuales del programa.

## Acciones en BD
- Al aprobar: Se marca `verified_by_human = 1` y `status = 'verified'` en `state/pipeline.db`.
- Al rechazar: Se marca `status = 'rejected'` con notas explicativas.
- Registro completo en `logs/audit.jsonl`.
