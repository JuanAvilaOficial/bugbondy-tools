---
name: 07-submit-track
description: Seguimiento del ciclo de vida del reporte enviado (triaje, resolución, duplicados, recompensas).
---

# 07 - Submit & Track

## Propósito
Gestionar el envío de reportes aprobados y monitorizar las respuestas, cambios de estado y recompensas en la plataforma de bug bounty.

## Tareas
- Registrar envíos en `state/pipeline.db` (tabla `submissions`).
- Actualizar el estado del reporte según feedback de la plataforma:
  - `pending`
  - `triaged`
  - `resolved`
  - `duplicate`
  - `informative`
  - `out_of_scope`
- Si un reporte es marcado como duplicado o informativo, almacenar el embedding en `state/vector-index/` para mejorar el triaje futuro.
- Registrar el monto de la recompensa (`bounty_amount`) cuando corresponda.
