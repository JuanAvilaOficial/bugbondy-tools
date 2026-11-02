-- 001_initial_schema.sql
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS assets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    program_id TEXT NOT NULL,
    asset_type TEXT NOT NULL CHECK (asset_type IN ('domain', 'ip', 'url', 'cidr', 'subdomain')),
    value TEXT NOT NULL UNIQUE,
    in_scope INTEGER NOT NULL DEFAULT 1 CHECK (in_scope IN (0, 1)),
    discovered_at TEXT NOT NULL DEFAULT (datetime('now')),
    metadata TEXT
);

CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    program_id TEXT NOT NULL,
    asset_id INTEGER,
    title TEXT NOT NULL,
    severity TEXT NOT NULL CHECK (severity IN ('info', 'low', 'medium', 'high', 'critical')),
    cvss REAL CHECK (cvss IS NULL OR (cvss >= 0.0 AND cvss <= 10.0)),
    cve TEXT,
    tool_source TEXT,
    description TEXT,
    proof_of_concept TEXT,
    status TEXT NOT NULL DEFAULT 'discovered' CHECK (status IN ('discovered', 'triaged', 'pending_verification', 'verified', 'rejected', 'reported', 'submitted')),
    verified_by_human INTEGER NOT NULL DEFAULT 0 CHECK (verified_by_human IN (0, 1)),
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now')),
    FOREIGN KEY (asset_id) REFERENCES assets(id) ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS approvals (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    finding_id INTEGER NOT NULL UNIQUE,
    operator TEXT NOT NULL,
    poc_hash TEXT NOT NULL,
    notes TEXT,
    approved_at TEXT NOT NULL DEFAULT (datetime('now')),
    FOREIGN KEY (finding_id) REFERENCES findings(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS submissions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    finding_id INTEGER NOT NULL,
    program_id TEXT NOT NULL,
    platform TEXT NOT NULL CHECK (platform IN ('hackerone', 'bugcrowd', 'intigriti', 'self-hosted', 'other')),
    platform_submission_id TEXT,
    status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'triaged', 'resolved', 'duplicate', 'informative', 'out_of_scope')),
    bounty_amount REAL DEFAULT 0.0 CHECK (bounty_amount >= 0.0),
    submitted_at TEXT,
    notes TEXT,
    FOREIGN KEY (finding_id) REFERENCES findings(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_assets_program ON assets(program_id);
CREATE INDEX IF NOT EXISTS idx_findings_program_status ON findings(program_id, status);
CREATE INDEX IF NOT EXISTS idx_findings_verified ON findings(verified_by_human);
CREATE INDEX IF NOT EXISTS idx_approvals_finding ON approvals(finding_id);
