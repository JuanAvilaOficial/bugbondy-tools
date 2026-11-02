# Bug Bounty Tools & Pipeline (bbpipeline)

Pipeline automatizado y orquestado para auditorías de seguridad y programas de Bug Bounty con gobernanza estricta, puntos de control (*gates*) humanos obligatorios, control de alcance *fail-closed* y registro de auditoría inmutable.

---

## 🏛️ Arquitectura del Sistema

El pipeline opera bajo un flujo de 8 etapas secuenciales coordinadas por el orquestador:

1. **`00-scope-manager`**: Fuente de verdad en `config/scope.yaml`. Valida targets antes de cualquier petición de red (*fail-closed*).
2. **`01-recon`**: Descubrimiento de activos y subdominios (`subfinder`).
3. **`02-fingerprint`**: Identificación pasiva de tecnologías y servicios (`amass`, `httpx`).
4. **`03-vuln-scan`**: Escaneo controlado con allowlist de plantillas Nuclei (`config/templates.yaml`).
5. **`04-triage`**: Deduplicación semántica y cálculo de CVSS.
6. **`05-verify` (GATE HUMANO OBLIGATORIO)**: Ningún proceso automatizado puede validar un hallazgo. Requiere aprobación explícita de un operador humano registrada en la tabla SQLite `approvals`.
7. **`06-report`**: Redacción formal del reporte técnico.
8. **`07-submit-track`**: Seguimiento del ciclo de vida del reporte en la plataforma receptora.

---

## 🛡️ Controles de Seguridad y Gobernanza

- **Scope Guard (`src/bbpipeline/scope.py`)**: Valida targets (wildcards, dominios exactos, URLs, rangos CIDR) con prioridad absoluta a exclusiones (*out of scope*) y protección anti-SSRF bloqueando IPs privadas y de metadatos de nube.
- **Triggers en Base de Datos (`state/migrations/002_human_gate_and_approvals.sql`)**: 
  - Bloquea transicionar un hallazgo a `verified`, `reported` o `submitted` si `verified_by_human = 0`.
  - Exige un registro previo e inmutable en la tabla `approvals` antes de autorizar la verificación.
- **Auditoría Criptográfica (`logs/audit.jsonl`)**: Cada evento se registra encadenado por hash SHA-256 (`prev_hash` -> `hash`). La integridad de la cadena se verifica con `bbp audit verify`.
- **Kill Switch**: Detección inmediata del archivo `STOP` para detener cualquier operación en curso.
- **Allowlist de Plantillas (`config/templates.yaml`)**: Previene la ejecución de plantillas agresivas o destructivas (DoS/DDoS).

---

## 🚀 Instalación y Puesta en Marcha

### Requisitos previos
- Python >= 3.11
- [uv](https://docs.astral.sh/uv/)

### Configuración inicial
```bash
# 1. Instalar dependencias del proyecto
uv sync

# 2. Diagnóstico de herramientas del sistema
uv run bbp doctor

# 3. Aplicar migraciones a la base de datos de estado
uv run bbp migrate
```

---

## 💻 Uso del CLI (`bbp`)

```bash
# Validar si un target está en alcance
uv run bbp check-scope api.example.com
uv run bbp check-scope support.example.com  # Falla: fuera de alcance

# Verificar integridad del log de auditoría
uv run bbp audit verify

# Registrar un evento en auditoría
uv run bbp audit log --stage 01-recon --event asset_discovered --target api.example.com

# Aprobar formalmente un hallazgo (Gate Humano)
uv run bbp approve 1 --operator "analyst1" --poc "poc.py" --notes "Validado en entorno de pruebas"

# Validar una plantilla de escaneo contra la allowlist
uv run bbp templates check cves/2021/CVE-2021-44228.yaml
```

---

## 🧪 Pruebas y Calidad de Código

```bash
# Ejecutar suite de pruebas completa
uv run pytest -v

# Linter y verificación de estilo
uv run ruff check .
```
