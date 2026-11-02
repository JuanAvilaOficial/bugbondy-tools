---
name: 01-recon
description: Descubrimiento de activos (subdominios, DNS, IPs, URLs) respetando el scope y rate limits.
---

# 01 - Reconnaissance

## Propósito
Realizar reconocimiento pasivo y activo para mapear la superficie de ataque dentro del alcance autorizado.

## Herramientas integradas
- Subdomain enumeration (subfinder, amass)
- DNS resolution (dnsx, massdns)
- Web probing (httpx)

## Reglas
- Pasar cada nuevo candidato por `00-scope-manager` antes de almacenar en base de datos.
- Respetar estrictamente los límites de velocidad definidos en `config/rate-limits.yaml`.
- Guardar los activos validados en `state/pipeline.db` (tabla `assets`).
