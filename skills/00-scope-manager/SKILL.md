---
name: 00-scope-manager
description: Valida y asegura el cumplimiento del alcance (scope) usando config/scope.yaml como fuente de verdad.
---

# 00 - Scope Manager

## Propósito
Garantizar que todo objetivo (dominio, subdominio, IP, URL o CIDR) analizado pertenezca estrictamente a la lista de activos permitidos (`in-scope`) y no forme parte de las exclusiones (`out-of-scope`).

## Entradas
- `config/scope.yaml`
- Activos descubiertos o propuestos para análisis

## Salidas
- Lista de activos validados in-scope en `state/pipeline.db`
- Registro de descartes out-of-scope en `logs/audit.jsonl`

## Reglas
- Cualquier activo ambiguo o out-of-scope debe ser descartado inmediatamente.
- Bloqueo preventivo antes de que cualquier otra etapa del pipeline procese el objetivo.
