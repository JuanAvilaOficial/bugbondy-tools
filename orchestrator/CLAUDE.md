# Reglas de Orquestación del Bug Bounty Pipeline

Este documento define la arquitectura de ejecución, el flujo secuencial de skills, los puntos de control (gates) de seguridad y las reglas obligatorias de gobernanza.

---

## 1. Orden de Ejecución de Skills

El pipeline sigue un flujo estricto y secuencial:

```
[00-scope-manager]
        │
        ▼
   [01-recon]
        │
        ▼
 [02-fingerprint]
        │
        ▼
  [03-vuln-scan]
        │
        ▼
   [04-triage]
        │
        ▼
======================================================
 [05-verify]  <--- 🛑 GATE HUMANO OBLIGATORIO (NO AUTOMATIZABLE)
======================================================
        │ (Solo si aprobado por humano)
        ▼
   [06-report]
        │
        ▼
[07-submit-track]
```

### Detalle de Fases:
1. **`00-scope-manager`**:
   - Fuente de verdad: `config/scope.yaml`.
   - Valida cada target antes de cualquier llamada de red.
   - Si no está explícitamente en scope, se detiene de inmediato.
2. **`01-recon`**:
   - Descubrimiento de subdominios, IPs, puertos y endpoints.
   - Aplica límites de velocidad de `config/rate-limits.yaml`.
3. **`02-fingerprint`**:
   - Identificación pasiva y no intrusiva de tecnologías, headers y servicios.
4. **`03-vuln-scan`**:
   - Ejecución acotada de escaneos automáticos de vulnerabilidades con templates preaprobados.
5. **`04-triage`**:
   - Reducción de falsos positivos y deduplicación semántica con `state/vector-index/`.
   - Cálculo de severidad CVSS preliminar.
6. **`05-verify` (GATE HUMANO OBLIGATORIO)**:
   - **REGLA ABSOLUTA:** Ningún agente ni proceso automatizado puede saltarse este paso ni autorizar un hallazgo por su cuenta.
   - Requiere validación manual por parte del operador humano (`verified_by_human = 1`).
   - Requiere un PoC reproducible y seguro.
7. **`06-report`**:
   - Redacción formal del reporte técnico siguiendo las directrices del programa.
8. **`07-submit-track`**:
   - Envío a la plataforma de Bug Bounty y seguimiento del ciclo de vida del reporte.

---

## 2. Gates y Controles de Seguridad

| Gate | Ubicación | Tipo | Condición de Aprobación |
| :--- | :--- | :--- | :--- |
| **Scope Gate** | Pre-01, Pre-02, Pre-03 | Automático | Coincidencia estricta en `config/scope.yaml` |
| **Rate Limit Gate** | Continuo (01 a 03) | Automático | Nunca superar peticiones/segundo definidas en `config/rate-limits.yaml` |
| **Deduplication Gate**| Fase 04 | Automático | Score de similitud en `vector-index` menor al umbral de duplicado |
| **Verification Gate** | **Fase 05** | **Manual / Humano** | Confirmación explícita del operador humano en base de datos y logs |
| **Submission Gate** | Pre-07 | Manual / Humano | Autorización final de envío al programa |

---

## 3. Registro de Auditoría (`logs/audit.jsonl`)

Toda acción tomada por cualquier agente o módulo debe registrarse de forma inmutable en `logs/audit.jsonl` con el siguiente esquema JSON:

```json
{
  "timestamp": "ISO-8601",
  "stage": "00-scope-manager | 01-recon | ...",
  "event": "target_checked | asset_discovered | scan_started | vuln_flagged | human_verified | report_generated",
  "target": "target.domain.com",
  "details": {},
  "actor": "agent | human"
}
```

---

## 4. Base de Datos de Estado (`state/pipeline.db`)

La base de datos SQLite almacena el ciclo de vida de los datos:
- `assets`: Activos descubiertos y su estatus de scope.
- `findings`: Hallazgos detectados, severidad, estado y flag `verified_by_human`.
- `submissions`: Estado de los envíos en las plataformas receptoras.

---

## 5. Servidores MCP Habilitados

La habilitación de herramientas externas MCP por fase se rige estrictamente por `config/mcp-servers.yaml`. Ningún agente debe invocar herramientas fuera de la fase para la que fueron autorizadas.

---

## 6. Estándar de Entorno y Ejecución con `uv`

Este proyecto estandariza el uso de **`uv`** como gestor único de entorno virtual, dependencias y ejecución de scripts de Python:

- **Ejecución de scripts:** Utilizar siempre `uv run <script.py>` para garantizar que las dependencias declaradas en `pyproject.toml` estén resueltas en el entorno.
- **Herramientas efímeras / CLI:** Utilizar `uvx <herramienta>` para ejecutar herramientas sin instalarlas globalmente.
- **Gestión de dependencias:** 
  - Añadir librerías: `uv add <paquete>`
  - Añadir herramientas de desarrollo: `uv add --dev <paquete>`
  - Sincronizar el entorno: `uv sync`
- **Configuración central:** El archivo `pyproject.toml` en la raíz del pipeline define los requisitos mínimos y versiones compatibles (Python >= 3.11).

