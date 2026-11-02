---
name: 02-fingerprint
description: Identificación de tecnologías, servicios, puertos y rutas clave sin enviar payloads intrusivos.
---

# 02 - Fingerprinting

## Propósito
Caracterizar los servicios y tecnologías expuestos en los activos descubiertos para alimentar las fases posteriores con contexto preciso.

## Tareas principales
- Detección de CMS, frameworks, lenguajes y librerías web (Wappalyzer, whatweb).
- Escaneo de puertos y detección de versiones de servicios (nmap/naabu en modo controlado).
- Análisis de cabeceras HTTP y certificados SSL/TLS.

## Reglas
- Ningún payload o escaneo destructivo en esta fase.
- Registrar metadatos asociados al activo en `state/pipeline.db`.
