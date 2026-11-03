"""CLI para la gestión, auditoría y gates de seguridad del Bug Bounty Pipeline."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from bbpipeline.audit import AuditLogger, verify_audit_file
from bbpipeline.db import Database, check_kill_switch
from bbpipeline.doctor import run_checks
from bbpipeline.scope import ScopeGuard, ScopeViolationError
from bbpipeline.templates import TemplateAllowlist, TemplateNotAllowedError


def cmd_migrate(args: argparse.Namespace) -> int:
    db = Database(args.db_path)
    applied = db.migrate(args.migrations_dir)
    if applied:
        print(f"✅ Migraciones aplicadas con éxito ({len(applied)}): {', '.join(applied)}")
    else:
        print("ℹ️  No hay migraciones pendientes. Esquema al día.")
    return 0


def cmd_scope_check(args: argparse.Namespace) -> int:
    if check_kill_switch():
        print("🛑 ALERTA: Kill switch activado (archivo STOP presente). Operación abortada.", file=sys.stderr)
        return 2

    guard = ScopeGuard(args.config)
    try:
        guard.validate_target(args.target, program_id=args.program, resolve_dns=args.resolve_dns)
        print(f"✅ Target en alcance (IN SCOPE): {args.target}")
        return 0
    except ScopeViolationError as e:
        print(f"❌ Target fuera de alcance (OUT OF SCOPE): {e}", file=sys.stderr)
        return 1
    except Exception as e:  # noqa: BLE001
        print(f"❌ Error al evaluar target: {e}", file=sys.stderr)
        return 1


def cmd_audit_verify(args: argparse.Namespace) -> int:
    is_valid, count, error = verify_audit_file(args.log_path)
    if is_valid:
        print(f"✅ Auditoría íntegra y verificada. Total de eventos encadenados válidos: {count}")
        return 0
    else:
        print(f"❌ Error de integridad en auditoría ({args.log_path}): {error}", file=sys.stderr)
        return 1


def cmd_audit_log(args: argparse.Namespace) -> int:
    logger = AuditLogger(args.log_path)
    details = {}
    if args.details:
        try:
            details = json.loads(args.details)
        except json.JSONDecodeError as e:
            print(f"Error parseando --details como JSON: {e}", file=sys.stderr)
            return 1

    entry = logger.log(
        stage=args.stage,
        event=args.event,
        target=args.target,
        actor=args.actor,
        details=details,
    )
    print(f"✅ Evento registrado con hash {entry['hash'][:12]}... (prev: {entry['prev_hash'][:12]}...)")
    return 0


def cmd_approve(args: argparse.Namespace) -> int:
    # Leer contenido del PoC (de archivo o texto directo)
    poc_path = Path(args.poc)
    if poc_path.exists() and poc_path.is_file():
        with open(poc_path, "r", encoding="utf-8") as f:
            poc_content = f.read()
    else:
        poc_content = args.poc

    db = Database(args.db_path)
    try:
        db.approve_finding_human_gate(
            finding_id=args.finding_id,
            operator=args.operator,
            poc_content=poc_content,
            notes=args.notes,
        )
        print(f"✅ Gate Humano Aprobado: Finding #{args.finding_id} verificado por operador '{args.operator}'.")

        # Registrar en auditoría
        logger = AuditLogger(args.log_path)
        logger.log(
            stage="05-verify",
            event="human_verified",
            target=f"finding:{args.finding_id}",
            actor=f"human:{args.operator}",
            details={"notes": args.notes},
        )
        return 0
    except Exception as e:  # noqa: BLE001
        print(f"❌ Fallo al aplicar aprobación de gate humano: {e}", file=sys.stderr)
        return 1


def cmd_doctor(args: argparse.Namespace) -> int:
    report = run_checks()
    all_ok = True
    for check in report.checks:
        icon = "✅" if check.status == "ok" else "❌"
        print(f"{icon} [{check.status.upper()}] {check.name}: {check.detail}")
        if check.status != "ok":
            all_ok = False

    if all_ok:
        print("✅ Doctor: entorno del pipeline íntegro (dependencias y herramientas OK).")
        return 0
    print("❌ Doctor: el entorno no está listo. Instale las herramientas/binarios faltantes.")
    return 1


def cmd_templates_check(args: argparse.Namespace) -> int:
    allowlist = TemplateAllowlist()
    try:
        allowlist.validate_template(args.template)
        print(f"✅ Plantilla en allowlist (AUTORIZADA): {args.template}")
        return 0
    except TemplateNotAllowedError as e:
        print(f"❌ Plantilla fuera de allowlist: {e}", file=sys.stderr)
        return 1


def cmd_mcp_server(args: argparse.Namespace) -> int:
    from bbpipeline.mcp_server import SecurityMCPServer

    server = SecurityMCPServer()
    server.run_stdio()
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(
        prog="bbp",
        description="Bug Bounty Pipeline CLI - Herramientas de gobernanza, auditoría y gates de seguridad",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    # Migraciones
    p_mig = subparsers.add_parser("migrate", help="Ejecutar migraciones de base de datos")
    p_mig.add_argument("--db-path", default="state/pipeline.db", help="Ruta a pipeline.db")
    p_mig.add_argument("--migrations-dir", default="state/migrations", help="Directorio de archivos SQL")
    p_mig.set_defaults(func=cmd_migrate)

    # Scope
    p_scope = subparsers.add_parser("check-scope", help="Validar si un target está dentro del alcance")
    p_scope.add_argument("target", help="Dominio, URL, IP o target a verificar")
    p_scope.add_argument("--program", default=None, help="ID del programa")
    p_scope.add_argument("--config", default="config/scope.yaml", help="Ruta al archivo scope.yaml")
    p_scope.add_argument("--resolve-dns", action="store_true", help="Resolver DNS y verificar IPs")
    p_scope.set_defaults(func=cmd_scope_check)

    # Audit
    p_audit = subparsers.add_parser("audit", help="Comandos de auditoría")
    audit_subs = p_audit.add_subparsers(dest="audit_action", required=True)

    p_a_ver = audit_subs.add_parser("verify", help="Verificar cadena de hashes del log de auditoría")
    p_a_ver.add_argument("--log-path", default="logs/audit.jsonl", help="Ruta al log de auditoría")
    p_a_ver.set_defaults(func=cmd_audit_verify)

    p_a_log = audit_subs.add_parser("log", help="Registrar un evento en auditoría")
    p_a_log.add_argument("--stage", required=True, help="Nombre de la etapa")
    p_a_log.add_argument("--event", required=True, help="Nombre del evento")
    p_a_log.add_argument("--target", required=True, help="Target involucrado")
    p_a_log.add_argument("--actor", default="agent", help="Actor que ejecuta la acción")
    p_a_log.add_argument("--details", default="{}", help="Detalles adicionales en JSON")
    p_a_log.add_argument("--log-path", default="logs/audit.jsonl", help="Ruta al log de auditoría")
    p_a_log.set_defaults(func=cmd_audit_log)

    # Gate Humano (Approve)
    p_app = subparsers.add_parser("approve", help="Aprobar formalmente un hallazgo (Gate Humano)")
    p_app.add_argument("finding_id", type=int, help="ID del hallazgo")
    p_app.add_argument("--operator", required=True, help="Nombre o identificador del operador humano")
    p_app.add_argument("--poc", required=True, help="PoC o ruta a archivo de PoC")
    p_app.add_argument("--notes", default=None, help="Notas adicionales de verificación")
    p_app.add_argument("--db-path", default="state/pipeline.db", help="Ruta a pipeline.db")
    p_app.add_argument("--log-path", default="logs/audit.jsonl", help="Ruta a audit.jsonl")
    p_app.set_defaults(func=cmd_approve)

    # Doctor (dependencias y herramientas)
    p_doc = subparsers.add_parser("doctor", help="Verificar dependencias y herramientas del pipeline")
    p_doc.set_defaults(func=cmd_doctor)

    # Allowlist de plantillas para escaneos externos
    p_tmpl = subparsers.add_parser("templates", help="Control de allowlist de plantillas de escaneo")
    p_tmpl_sub = p_tmpl.add_subparsers(dest="templates_action", required=True)
    p_tmpl_check = p_tmpl_sub.add_parser("check", help="Validar una plantilla contra la allowlist")
    p_tmpl_check.add_argument("template", help="Plantilla a validar (ej. cves/2021/CVE-2021-44228.yaml)")
    p_tmpl_check.set_defaults(func=cmd_templates_check)

    # Servidor MCP stdio
    p_mcp = subparsers.add_parser("mcp-server", help="Ejecutar servidor MCP JSON-RPC 2.0 sobre stdio")
    p_mcp.set_defaults(func=cmd_mcp_server)

    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
