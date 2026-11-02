---
name: 06-report
description: Generación de reportes técnicos de alta calidad con PoC, impacto y recomendaciones de mitigación.
---

# 06 - Report

## Propósito
Redactar reportes profesionales listos para enviar a plataformas de bug bounty (HackerOne, Bugcrowd, etc.) para hallazgos que hayan superado el Gate Humano (`verified_by_human = 1`).

## Estructura del Reporte
1. **Resumen Ejecutivo:** Descripción concisa de la vulnerabilidad y el impacto.
2. **Severidad y CVSS:** Puntuación justificada con vector CVSS.
3. **Activo Afectado:** URL/IP/Endpoint exacto en alcance.
4. **Pasos para Reproducir (PoC):** Instrucciones claras, scripts curl/HTTP requests, evidencias y capturas.
5. **Impacto en el Negocio:** Consecuencias reales si es explotada.
6. **Remediación:** Pasos técnicos específicos para corregir la falla.

## Reglas
- No generar reportes automáticos para hallazgos no verificados por humanos.
- Almacenar el reporte generado y actualizar estado a `reported` en `state/pipeline.db`.
