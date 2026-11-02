---
name: 04-triage
description: Filtrado automático de falsos positivos, deduplicación y priorización por severidad/CVSS.
---

# 04 - Triage

## Propósito
Analizar los hallazgos brutos procedentes de los escaneos para eliminar falsos positivos, calcular severidad y evitar duplicados.

## Tareas
- Comparación semántica contra reportes previos usando `state/vector-index/`.
- Verificación sintáctica básica de respuestas HTTP / evidencias.
- Asignación de severidad preliminar y CVSS v3.1.
- Actualización de estado en `state/pipeline.db` a `triaged` o `rejected`.
