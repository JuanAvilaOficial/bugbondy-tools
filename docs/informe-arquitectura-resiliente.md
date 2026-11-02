# Informe Técnico: Arquitectura de Software y Red Resiliente
**Frente a Ciberataques Modernos — Diseño Defensivo en los 5 Pilares Arquitectónicos**

| Campo | Valor |
| :--- | :--- |
| **Documento** | Informe técnico de arquitectura defensiva |
| **Estado** | Borrador para revisión del equipo |
| **Fecha** | 2026-11-02 |
| **Alcance** | Consistencia de parsers, fuente de verdad del servidor, segmentación/red Zero Trust, gobierno de agentes de IA, DevSecOps continuo |
| **Audiencia** | Equipo de ingeniería, equipo de seguridad, arquitectura |

---

## 1. Objetivo y Alcance

Ante los vectores de ataque modernos —*HTTP Request Smuggling*, *parser differentials*, *WAF evasion*, *mass assignment*, *race conditions*, *SSRF*, *prompt injection indirecta* y *inestabilidad de memoria*—, el diseño defensivo debe eliminar las **desalineaciones entre componentes intermedios**, **centralizar la confianza en el servidor** y **segmentar las fronteras de ejecución**.

Este informe formaliza los **5 pilares arquitectónicos** propuestos, cada uno con sus controles de diseño y patrones de remediación asociados.

---

## 2. Pilar 1 — Consistencia de Parsers y Normalización Canónica

**Problema base:** Proxy de borde, CDN y backend interpretan el mismo payload de forma distinta. El desajuste sintáctico (p. ej., `Transfer-Encoding: chunked` vs. `Content-Length`, orquestación de headers) habilita *smuggling*.

### 2.1 Modelo de parsing único o canónico

- Designar **un único componente orquestador** (gateway/edge) con el parser canónico de referencia.
- El backend **no mantiene un parser paralelo**: delega o comparte la misma librería/parser validado.
- Política de versionado: solo se acepta el dialecto parser soportado por la versión canónica.

### 2.2 Minimización de parsers intermedios

- Reducir la cadena de procesamiento previo al backend (CDN → WAF → proxy interno → backend).
- Hardening: deshabilitar funcionalidades de transformación no usadas (re-escritura, compresión, decodificación) en proxies innecesarios.
- Eliminar librerías de conversión intermedias que generen *diferenciales* sintácticos.

### 2.3 Normalización previa a validación

Toda entrada debe pasar por el pipeline:

```
Normalizar → Validar → Autorizar → Almacenar/Responder
```

- **URLs:** normalización de rutas (eliminación de segmentos duplicados, canonicalización, IDNA), antes de reglas de allowlist.
- **Headers:** unificación de formatos (obs-fold, casing), límite de longitud y rechazo de valores no canónicos.
- **Multipart/JSON:** límites de tamaño y conteo de partes, JSON canónico (key ordering, número de precisión).

### 2.4 Reescritura directa

- Si el proxy/CDN limpia o transforma la petición, debe modificar **la petición real enviada al servidor interno** (p. ej., `proxy_set_header`, reglas de rewrite en nginx).
- No basta con reescribir la *cache key*: el payload efectivo debe reflejarse en el tráfico interno.

### 2.5 Checklist del Pilar 1

- [ ] Un solo parser canónico declarado y versionado.
- [ ] Cadena de proxies/WAF minimizada y auditable.
- [ ] Regla de normalización documentada antes de cada validación.
- [ ] Reescritura verificada en tráfico interno (no solo en caché).

---

## 3. Pilar 2 — El Servidor como Única Fuente de Verdad (Lógica de Negocio)

**Problema base:** Lógica de negocio derivada de datos del cliente → vulnerabilidades lógicas y de estado no detectadas por escáneres automatizados.

### 3.1 Invariantes en el servidor

- **Nunca confiar** en datos provenientes del cliente (precios, cantidades, roles, permisos).
- Revalidar y **recomputar** siempre la información desde la base de datos *authoritative*.
- Anti-patrón a eliminar: reflejar campos del body en respuestas o decisiones.

### 3.2 Máquinas de Estados Finitos (FSM) explícitas

- Modelar flujos multietapa estrictos (p. ej., `PENDIENTE → AUTORIZADO → PAGADO`).
- Rechazar transiciones no autorizadas; el backend es la única fuente de transición válida.

```text
PENDIENTE ──► AUTORIZADO ──► PAGADO
     │                │
     └────► RECHAZADO ◄┘
```

- Toda transición persistida con actor, timestamp y estado previo (traza para auditoría).

### 3.3 Operaciones atómicas e idempotencia

- **Claves de idempotencia** (`Idempotency-Key`) en endpoints críticos (pagos, pedidos, reinicios).
- **Transacciones** con `SELECT ... FOR UPDATE` o bloqueo optimista (campos `version`).
- Patrón *outbox* para acciones que publican eventos de dominio.

### 3.4 Listas de atributos permitidos (DTOs)

- Rechazar *mass assignment*: DTOs explícitos con allowlist de campos.
- Serializers con campos restringidos; nunca vincular entidades completas desde el payload.

### 3.5 Checklist del Pilar 2

- [ ] Entrada de cliente nunca usada como fuente autoritativa.
- [ ] FSM versionada con estados y transiciones validadas en servidor.
- [ ] Idempotencia implementada en operaciones de efecto.
- [ ] DTOs con allowlist en endpoints de escritura.

---

## 4. Pilar 3 — Segmentación de Red y Modelo Zero Trust (Mitigación de SSRF)

**Problema base:** Falsificación de Peticiones del Lado del Servidor (SSRF) y contrabando de protocolos (file://, gopher://, redis://) hacia la red interna.

### 4.1 Aislamiento de la red interna

- **Firewall estricto** y microsegmentación: el servidor web solo puede alcanzar lo necesario (puertos/services permitidos).
- Políticas *egress*: deny-by-default hacia subredes internas no productivas.

### 4.2 Validación de peticiones salientes

- Si la app consume URLs externas, validar la IP/hostname de destino **tras la resolución DNS**.
- Excluir rangos privados, loopback, link-local, multicast y **metadatos** (`169.254.169.254`).
- Nunca reutilizar la cadena de URL del cliente directamente.

### 4.3 Arquitectura Zero Trust

- Autenticación y autorización explícitas **en cada frontera de servicio**.
- Front-end y componentes de borde: sin confianza implícita en llamadas al backend.

### 4.4 Checklist del Pilar 3

- [ ] Reglas egress y segmentación aplicadas (deny-by-default).
- [ ] Validación post-DNS con bloqueo de rangos internos.
- [ ] Control de acceso por llamada entre servicios.

---

## 5. Pilar 4 — Gobierno y Contención de Agentes de IA

**Problema base:** Agentes autónomos con identidades privilegiadas → superficie de ataque ampliada por inyección indirecta de prompts.

### 5.1 Agentes como identidades privilegiadas

- Permisos **mínimos necesarios** por agente (principio de menor privilegio, *purpose binding*).
- Agentes no usan credenciales de administrador; accesos se conceden por tarea y rotan.

### 5.2 Aislamiento de contexto y SOP

- Contenido web no confiable **separado** de instrucciones de ejecución.
- Canales y sandboxes separados; contenido inyectado no debe poder alterar el orquestador de acciones.

### 5.3 Mecanismos de desconexión (*kill switch*)

- Límites de volumen (tokens, peticiones, recursos compartidos).
- Detección de comportamiento anómalo → interrupción inmediata vía API/circuit breaker.

### 5.4 Checklist del Pilar 4

- [ ] Modelo de permisos por propósito para agentes.
- [ ] Separación de datos no confiables / instrucciones de sistema.
- [ ] Presets de budget y *kill switch* operativos.

---

## 6. Pilar 5 — DevSecOps y Análisis Continuo

### 6.1 Lenguajes seguros y verificación

- Migrar componentes críticos a **lenguajes con seguridad de memoria** (Rust, Go, Java, WASM; evitar C/C++ en lógica de seguridad).
- Aplicar **verificación formal** cuando proceda (model checking, TLA+/Petri nets) en flujos críticos.

### 6.2 Análisis estático semántico (AST)

- Incorporar **Semgrep** / **CodeQL** / equivalentes para auditar flujo de datos y validar controles de seguridad.
- Revisión de llamadas **interprocedurales**: asegurar que los controles no se omiten en funciones callee.

### 6.3 Fuzzing diferencial automatizado

- Pruebas continuas que comparen respuestas de **diferentes combinaciones** de proxies/servidores ante entradas al límite de la especificación RFC.
- Fuzzing de parsers y de smuggling (mismos payloads con variaciones de framing).

### 6.4 Checklist del Pilar 5

- [ ] Lenguajes y perfiles de memoria definidos para componentes críticos.
- [ ] Reglas Semgrep/CodeQL en CI (fail on new findings).
- [ ] Suite de fuzzing diferencial en pipeline CI.

---

## 7. Matriz de Riesgos y Controles (mapeo por vector de ataque)

| Vector de ataque | Pilar | Control propuesto | Patrón de remediación | Prioridad |
| :--- | :--- | :--- | :--- | :--- |
| HTTP Request Smuggling | 1 | Parser canónico único | Coherencia CL.TE/proxy, normalización previa | Alta |
| Parser differentials | 1 | Parsing canónico | Single source of truth parser, minimizar librerías | Alta |
| Evasión de WAF | 1 | Normalización canónica | Normalizar antes de validar, rewrite directo | Alta |
| Mass assignment | 2 | DTOs allowlist | Bind explícito de campos | Alta |
| Race conditions / pagos | 2 | Idempotencia + transacciones | `Idempotency-Key`, `FOR UPDATE`/optimista | Alta |
| FSM inválida | 2 | Máquinas de estados finitas | Transiciones server-side restringidas | Media |
| SSRF / protocolos internos | 3 | Segmentación + validación saliente | Firewall egress, validación post-DNS, Zero Trust | Crítica |
| Inyección indirecta (IA) | 4 | Aislamiento contexto/SOP, kill switch | Sandboxing, purpose binding, budgets | Alta |
| Errores de memoria | 5 | Lenguajes seguros, verificación | Rust/Go/Java crítico, formal | Media |

---

## 8. Roadmap de Implementación (sugerido)

| Fase | Objetivo | Entregables |
| :--- | :--- | :--- |
| **0** | Baseline de gobernanza | Inventario de parsers, proxies, WAFs; política de normalización |
| **1** | Consistencia de parsers | Parser canónico, reglas de rewrite, pruebas de smuggling |
| **2** | Fuente de verdad del servidor | FSM, DTOs, idempotencia, invariantes de negocio |
| **3** | Red Zero Trust / SSRF | Egress policy, validación DNS, segmentación |
| **4** | Agentes de IA | Permisos por propósito, aislamiento, kill switch |
| **5** | DevSecOps continuo | Semgrep/CodeQL en CI, fuzzing diferencial, verificación formal |

> Cada fase debe operar bajo el **gate humano** del proceso de Bug Bounty (equivalente al gate de verificación) antes de cambios que afecten producción.

---

## 9. Conclusión

La resiliencia defensiva no es un producto, sino un **estado de consistencia**: un solo modelo de decisión, una única fuente de verdad y fronteras bien segmentadas. Los cinco pilares deben implementarse como **controles transversales**, no como capas aisladas.

---

## Apéndices

### A. Política mínima de normalización (ejemplo)
```yaml
# Ejemplo conceptual de política de normalización
normalize:
  - url: canonicalize
  - headers: unify_folding, reject_obs_fold
  - multipart: enforce_size_limit
validate:
  - after_normalize: true
rewrite:
  - internal_target_only: true
```

### B. Esquema de idempotencia mínima
```text
Idempotency-Key: <UUID>
Idempotency-Key + Request-Hash → lookup en store (TTL)
Misma key + hash distinto → 409 Conflict
Misma key + hash igual → reintentar con mismo resultado (idempotente)
```

### C. Validación de destino saliente (pseudocódigo)
```python
def is_safe_target(url: str) -> bool:
    host = resolve_hostname(url.hostname)   # DNS real
    if ip_address(host) in PRIVATE_RANGES: return False
    if ip_address(host) == METADATA_IP: return False
    return True
```

---

**Próximo paso sugerido:** convertir este informe en `docs/` dentro del repositorio del pipeline, con anexos de configuración por programa (scope, rate limits, MCP servers) y actualizar la matriz conforme se validen hallazgos en el campo.
