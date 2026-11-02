-- 002_human_gate_and_approvals.sql
PRAGMA foreign_keys = ON;

-- Trigger 1: Bloquear transición a estados protegidos si no hay verificación humana
CREATE TRIGGER IF NOT EXISTS trg_findings_enforce_human_verification
BEFORE UPDATE OF status ON findings
FOR EACH ROW
WHEN NEW.status IN ('reported', 'submitted', 'verified') AND NEW.verified_by_human = 0
BEGIN
    SELECT RAISE(ABORT, 'GATE VIOLATION: No se puede cambiar a verified, reported o submitted sin verificacion humana previa (verified_by_human=0).');
END;

-- Trigger 2: Exigir registro previo en tabla approvals antes de marcar verified_by_human=1
CREATE TRIGGER IF NOT EXISTS trg_findings_require_approval_record
BEFORE UPDATE OF verified_by_human ON findings
FOR EACH ROW
WHEN NEW.verified_by_human = 1
BEGIN
    SELECT CASE
        WHEN (SELECT COUNT(*) FROM approvals WHERE finding_id = NEW.id) = 0
        THEN RAISE(ABORT, 'GATE VIOLATION: Se requiere un registro de aprobacion formal en la tabla approvals antes de marcar verified_by_human=1.')
    END;
END;

-- Trigger 3: Bloquear creación inicial de findings con verified_by_human=1 o status protegido
CREATE TRIGGER IF NOT EXISTS trg_findings_prevent_insert_verified
BEFORE INSERT ON findings
FOR EACH ROW
WHEN NEW.verified_by_human = 1 OR NEW.status IN ('verified', 'reported', 'submitted')
BEGIN
    SELECT RAISE(ABORT, 'GATE VIOLATION: Un nuevo finding no puede crearse directamente verificado o reportado.');
END;

-- Trigger 4: Inmutabilidad de la tabla approvals (no UPDATE)
CREATE TRIGGER IF NOT EXISTS trg_approvals_prevent_update
BEFORE UPDATE ON approvals
FOR EACH ROW
BEGIN
    SELECT RAISE(ABORT, 'GOVERNANCE VIOLATION: Los registros de aprobacion humana son inmutables y no se pueden modificar.');
END;
