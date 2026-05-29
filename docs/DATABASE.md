# Database

## Full schema

```
tenants
  id          uuid PK
  name        varchar
  slug        varchar UNIQUE
  created_at  timestamptz

users
  id              uuid PK
  tenant_id       uuid FK→tenants       ← ALWAYS filter by this field
  email           varchar UNIQUE
  google_id       varchar UNIQUE NULL   ← NULL for GitHub-only users; "dev:<uuid>" for dev
  github_user_id  bigint UNIQUE NULL
  github_login    varchar NULL
  auth_provider   varchar NOT NULL DEFAULT 'google'  ← google|github|dev
  name            varchar
  avatar_url      text
  role            enum(owner,admin,member)
  created_at      timestamptz

org_members                         ← snapshot of GitHub org members per org
  id              uuid PK
  org_id          uuid FK→organizations
  tenant_id       uuid FK→tenants
  github_user_id  bigint
  github_login    varchar
  name            varchar
  avatar_url      text
  user_id         uuid FK→users NULL   ← populated when member has logged in
  is_active       bool
  last_synced_at  timestamptz
  created_at      timestamptz
  UNIQUE(org_id, github_user_id)

team_members
  team_id         uuid FK→teams
  org_member_id   uuid FK→org_members
  last_synced_at  timestamptz
  PK(team_id, org_member_id)

organizations
  id                         uuid PK
  tenant_id                  uuid FK→tenants
  github_org_login           varchar
  github_app_installation_id bigint NULL   ← NULL = app not installed
  scan_cron                  varchar       ← e.g. "0 2 * * *"
  is_active                  bool
  created_at                 timestamptz
  UNIQUE(tenant_id, github_org_login)

repositories
  id             uuid PK
  org_id         uuid FK→organizations
  github_repo_id bigint
  full_name      varchar               ← "owner/repo"
  default_branch varchar
  is_archived    bool
  is_monorepo    bool                  ← updated after first scan
  last_scanned_at timestamptz NULL
  created_at     timestamptz
  UNIQUE(org_id, github_repo_id)

scan_jobs
  id           uuid PK
  repo_id      uuid FK→repositories
  status       enum(pending,running,completed,failed)
  triggered_by enum(scheduled,manual,webhook)
  commit_sha   varchar
  started_at   timestamptz NULL
  completed_at timestamptz NULL
  error_msg    text NULL
  created_at   timestamptz

manifests
  id        uuid PK
  repo_id   uuid FK→repositories
  path      varchar    ← relative to repo root, e.g. "services/auth/go.mod"
  ecosystem varchar    ← "Go", "npm", "PyPI", etc.
  created_at timestamptz
  UNIQUE(repo_id, path)

teams
  id               uuid PK
  org_id           uuid FK→organizations
  github_team_slug varchar    ← e.g. "platform" (from @acme/platform)
  display_name     varchar
  created_at       timestamptz
  UNIQUE(org_id, github_team_slug)

findings
  id              uuid PK
  scan_job_id     uuid FK→scan_jobs
  manifest_id     uuid FK→manifests
  osv_id          varchar    ← e.g. "GHSA-xxxx" or "CVE-2023-xxxx"
  package_name    varchar
  package_version varchar
  fixed_version   varchar NULL
  severity        enum(critical,high,medium,low,unknown)
  cvss_score      numeric(4,1) NULL
  summary         text
  details         text
  status          enum(open,suppressed,fixed)
  first_seen_at   timestamptz
  last_seen_at    timestamptz

finding_teams                       ← N:N join table
  finding_id         uuid FK→findings
  team_id            uuid FK→teams
  codeowners_pattern varchar        ← pattern that matched
  PK(finding_id, team_id)
```

## Relationships

```
tenants
  └── users (many)
  └── organizations (many)
        └── repositories (many)
        │     └── manifests (many)
        │     └── scan_jobs (many)
        │           └── findings (many)
        │                 └── finding_teams (many) → teams
        └── teams (many)
              └── team_members (many) → org_members → users (optional)
        └── org_members (many)
```

## Common queries

### Dashboard: count by severity (tenant)
```sql
SELECT severity, COUNT(*) 
FROM findings f
JOIN manifests m ON m.id = f.manifest_id
JOIN repositories r ON r.id = m.repo_id
JOIN organizations o ON o.id = r.org_id
WHERE o.tenant_id = $1 AND f.status = 'open'
GROUP BY severity;
```

### Filtered findings with repo and manifest
```sql
SELECT f.*, r.full_name, m.path
FROM findings f
JOIN manifests m ON m.id = f.manifest_id
JOIN repositories r ON r.id = m.repo_id
JOIN organizations o ON o.id = r.org_id
WHERE o.tenant_id = $1
  AND ($2 = '' OR f.severity = $2)
  AND ($3 = '' OR f.status = $3)
ORDER BY f.last_seen_at DESC
LIMIT 500;
```

### Teams with count by severity
```sql
SELECT t.id, t.display_name,
  COUNT(f.id) FILTER (WHERE f.severity = 'critical' AND f.status = 'open'),
  COUNT(f.id) FILTER (WHERE f.severity = 'high' AND f.status = 'open'),
  ...
FROM teams t
JOIN organizations o ON o.id = t.org_id
LEFT JOIN finding_teams ft ON ft.team_id = t.id
LEFT JOIN findings f ON f.id = ft.finding_id
WHERE o.tenant_id = $1
GROUP BY t.id;
```

## Existing indexes

All indexes follow the pattern `idx_<table>_<column>`:

```sql
idx_users_tenant_id
idx_users_google_id
idx_users_github_user_id
idx_users_github_login
idx_users_auth_provider
idx_org_members_org_id, idx_org_members_tenant_id, idx_org_members_github_user_id
idx_team_members_org_member_id
idx_organizations_tenant_id
idx_repositories_org_id
idx_repositories_full_name
idx_scan_jobs_repo_id, idx_scan_jobs_status, idx_scan_jobs_created_at
idx_manifests_repo_id
idx_teams_org_id
idx_findings_scan_job_id, idx_findings_manifest_id
idx_findings_osv_id, idx_findings_severity, idx_findings_status
idx_finding_teams_team_id
```

## Conventions for new tables

1. Always add `tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE`
2. PK always `id UUID PRIMARY KEY DEFAULT gen_random_uuid()`
3. Timestamps `TIMESTAMPTZ NOT NULL DEFAULT NOW()`
4. Create an index on `tenant_id` and on every FK used in frequent JOINs
5. Soft delete: prefer an `is_active bool` column or `deleted_at timestamptz NULL` over a hard DELETE
6. Enums: use `CHECK (col IN (...))` instead of a PostgreSQL `ENUM` type (easier to migrate)
