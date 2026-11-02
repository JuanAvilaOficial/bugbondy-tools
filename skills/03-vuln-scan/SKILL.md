---
name: 03-vuln-scan
description: Escaneo automatizado de vulnerabilidades conocidas y desconfiguraciones según plantillas autorizadas.
---

# 03 - Vulnerability Scanning

## Propósito
Detectar posibles vulnerabilidades, desconfiguraciones y exposiciones mediante ejecución controlada de herramientas y plantillas validadas.

## Herramientas integradas
- Nuclei (plantillas verificadas, evitando DoS y tags rce/fuzz destructivos)
- FFUF (fuzzing acotado con listas curadas)

## Reglas
- Respetar los `rate-limits.yaml` de la herramienta y del programa.
- Excluir tipos de vulnerabilidades fuera de alcance indicadas en `config/scope.yaml`.
- Guardar candidatos a hallazgos en `state/pipeline.db` con estado `discovered`.
