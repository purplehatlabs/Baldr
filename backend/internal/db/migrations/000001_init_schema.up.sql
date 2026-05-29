-- Enable UUID extension
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- =============================================
-- TENANTS
-- =============================================
CREATE TABLE tenants (
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name       VARCHAR(255) NOT NULL,
    slug       VARCHAR(255) NOT NULL UNIQUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- =============================================
-- USERS
-- =============================================
CREATE TABLE users (
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id  UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    email      VARCHAR(255) NOT NULL UNIQUE,
    google_id  VARCHAR(255) NOT NULL UNIQUE,
    name       VARCHAR(255) NOT NULL,
    avatar_url TEXT NOT NULL DEFAULT '',
    role       VARCHAR(50) NOT NULL DEFAULT 'member' CHECK (role IN ('owner', 'admin', 'member')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_users_tenant_id ON users(tenant_id);
CREATE INDEX idx_users_google_id ON users(google_id);

-- =============================================
-- ORGANIZATIONS (GitHub orgs per tenant)
-- =============================================
CREATE TABLE organizations (
    id                         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id                  UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    github_org_login           VARCHAR(255) NOT NULL,
    github_app_installation_id BIGINT,
    scan_cron                  VARCHAR(100) NOT NULL DEFAULT '0 2 * * *',
    is_active                  BOOLEAN NOT NULL DEFAULT TRUE,
    created_at                 TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(tenant_id, github_org_login)
);

CREATE INDEX idx_organizations_tenant_id ON organizations(tenant_id);

-- =============================================
-- REPOSITORIES
-- =============================================
CREATE TABLE repositories (
    id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id         UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    github_repo_id BIGINT NOT NULL,
    full_name      VARCHAR(500) NOT NULL,
    default_branch VARCHAR(255) NOT NULL DEFAULT 'main',
    is_archived    BOOLEAN NOT NULL DEFAULT FALSE,
    is_monorepo    BOOLEAN NOT NULL DEFAULT FALSE,
    last_scanned_at TIMESTAMPTZ,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(org_id, github_repo_id)
);

CREATE INDEX idx_repositories_org_id ON repositories(org_id);
CREATE INDEX idx_repositories_full_name ON repositories(full_name);

-- =============================================
-- SCAN JOBS
-- =============================================
CREATE TABLE scan_jobs (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    repo_id      UUID NOT NULL REFERENCES repositories(id) ON DELETE CASCADE,
    status       VARCHAR(50) NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','running','completed','failed')),
    triggered_by VARCHAR(50) NOT NULL DEFAULT 'manual' CHECK (triggered_by IN ('scheduled','manual','webhook')),
    commit_sha   VARCHAR(40) NOT NULL DEFAULT '',
    started_at   TIMESTAMPTZ,
    completed_at TIMESTAMPTZ,
    error_msg    TEXT,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_scan_jobs_repo_id ON scan_jobs(repo_id);
CREATE INDEX idx_scan_jobs_status ON scan_jobs(status);
CREATE INDEX idx_scan_jobs_created_at ON scan_jobs(created_at DESC);

-- =============================================
-- MANIFESTS (per-path, supports monorepo)
-- =============================================
CREATE TABLE manifests (
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    repo_id    UUID NOT NULL REFERENCES repositories(id) ON DELETE CASCADE,
    path       VARCHAR(1000) NOT NULL,
    ecosystem  VARCHAR(100) NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(repo_id, path)
);

CREATE INDEX idx_manifests_repo_id ON manifests(repo_id);

-- =============================================
-- TEAMS (from CODEOWNERS)
-- =============================================
CREATE TABLE teams (
    id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id           UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    github_team_slug VARCHAR(255) NOT NULL,
    display_name     VARCHAR(255) NOT NULL,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(org_id, github_team_slug)
);

CREATE INDEX idx_teams_org_id ON teams(org_id);

-- =============================================
-- FINDINGS
-- =============================================
CREATE TABLE findings (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_job_id     UUID NOT NULL REFERENCES scan_jobs(id) ON DELETE CASCADE,
    manifest_id     UUID NOT NULL REFERENCES manifests(id) ON DELETE CASCADE,
    osv_id          VARCHAR(255) NOT NULL,
    package_name    VARCHAR(500) NOT NULL,
    package_version VARCHAR(255) NOT NULL,
    fixed_version   VARCHAR(255),
    severity        VARCHAR(50) NOT NULL DEFAULT 'unknown' CHECK (severity IN ('critical','high','medium','low','unknown')),
    cvss_score      NUMERIC(4,1),
    summary         TEXT NOT NULL DEFAULT '',
    details         TEXT NOT NULL DEFAULT '',
    status          VARCHAR(50) NOT NULL DEFAULT 'open' CHECK (status IN ('open','suppressed','fixed')),
    first_seen_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_findings_scan_job_id ON findings(scan_job_id);
CREATE INDEX idx_findings_manifest_id ON findings(manifest_id);
CREATE INDEX idx_findings_osv_id ON findings(osv_id);
CREATE INDEX idx_findings_severity ON findings(severity);
CREATE INDEX idx_findings_status ON findings(status);

-- =============================================
-- FINDING <-> TEAM mapping (via CODEOWNERS)
-- =============================================
CREATE TABLE finding_teams (
    finding_id         UUID NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
    team_id            UUID NOT NULL REFERENCES teams(id) ON DELETE CASCADE,
    codeowners_pattern VARCHAR(1000) NOT NULL DEFAULT '',
    PRIMARY KEY (finding_id, team_id)
);

CREATE INDEX idx_finding_teams_team_id ON finding_teams(team_id);
