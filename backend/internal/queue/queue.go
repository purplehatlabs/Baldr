package queue

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/hibiken/asynq"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/purplehatlabs/Baldr/internal/codeowners"
	"github.com/purplehatlabs/Baldr/internal/config"
	findingsvc "github.com/purplehatlabs/Baldr/internal/findings"
	githubclient "github.com/purplehatlabs/Baldr/internal/github"
	"github.com/purplehatlabs/Baldr/internal/models"
	repositoriesvc "github.com/purplehatlabs/Baldr/internal/repositories"
	"github.com/purplehatlabs/Baldr/internal/scanner"
	"go.uber.org/zap"
)

const (
	QueueScan    = "scan"
	QueueDefault = "default"

	TaskScanRepo = "scan:repo"
)

type ScanRepoPayload struct {
	RepoID  string `json:"repo_id"`
	Trigger string `json:"trigger"`
	JobID   string `json:"job_id,omitempty"`
}

func NewScanRepoTask(repoID, trigger, jobID string) (*asynq.Task, error) {
	payload, err := json.Marshal(ScanRepoPayload{RepoID: repoID, Trigger: trigger, JobID: jobID})
	if err != nil {
		return nil, fmt.Errorf("marshal payload: %w", err)
	}
	return asynq.NewTask(TaskScanRepo, payload, asynq.Queue(QueueScan)), nil
}

type scanRepoHandler struct {
	db             *pgxpool.Pool
	github         *githubclient.Client
	cfg            *config.Config
	log            *zap.Logger
	enqueuer       *Enqueuer
	analysis       *findingsvc.Service
	prioritization *findingsvc.PrioritizationService
}

func RegisterHandlers(
	mux *asynq.ServeMux,
	db *pgxpool.Pool,
	ghClient *githubclient.Client,
	cfg *config.Config,
	enqueuer *Enqueuer,
	log *zap.Logger,
) {
	h := &scanRepoHandler{
		db:             db,
		github:         ghClient,
		cfg:            cfg,
		log:            log,
		enqueuer:       enqueuer,
		analysis:       findingsvc.NewService(db, cfg, ghClient, log),
		prioritization: findingsvc.NewPrioritizationService(db),
	}
	mux.HandleFunc(TaskScanRepo, h.Handle)
	RegisterAnalysisHandlers(mux, db, ghClient, cfg, log)
	RegisterMetricsSnapshotHandlers(mux, db, log)
	RegisterExceptionExpiryHandlers(mux, db, log)
	RegisterThreatIntelHandlers(mux, db, log)
	RegisterMaliciousDatasetHandlers(mux, db, cfg, log)
	RegisterMembershipSyncHandlers(mux, db, ghClient, log)
	RegisterPackageDynamicAnalysisHandlers(mux, db, cfg, log)
}

func (h *scanRepoHandler) Handle(ctx context.Context, t *asynq.Task) error {
	var payload ScanRepoPayload
	if err := json.Unmarshal(t.Payload(), &payload); err != nil {
		return fmt.Errorf("unmarshal payload: %w", err)
	}

	repoID, err := uuid.Parse(payload.RepoID)
	if err != nil {
		return fmt.Errorf("parse repo_id: %w", err)
	}

	log := h.log.With(zap.String("repo_id", payload.RepoID))
	log.Info("starting scan")

	// --- 1. Load repo + org + tenant info ---
	type repoRow struct {
		FullName             string
		DefaultBranch        string
		OrgID                uuid.UUID
		TenantID             uuid.UUID
		GithubOrgLogin       string
		GithubInstallationID *int64
	}
	var row repoRow
	err = h.db.QueryRow(ctx, `
		SELECT r.full_name, r.default_branch, r.org_id,
		       o.tenant_id, o.github_org_login, o.github_app_installation_id
		FROM repositories r
		JOIN organizations o ON o.id = r.org_id
		WHERE r.id = $1`, repoID,
	).Scan(&row.FullName, &row.DefaultBranch, &row.OrgID,
		&row.TenantID, &row.GithubOrgLogin, &row.GithubInstallationID)
	if err != nil {
		return fmt.Errorf("load repo: %w", err)
	}
	if row.TenantID == uuid.Nil {
		log.Error("scan blocked: organization has no tenant_id",
			zap.String("org_id", row.OrgID.String()),
			zap.String("repo_full_name", row.FullName),
		)
		return fmt.Errorf("scan blocked: organization %s has no tenant_id", row.OrgID)
	}
	if err := repositoriesvc.EnsureRepoScannable(ctx, h.db, repoID); err != nil {
		if errors.Is(err, repositoriesvc.ErrScanBlockedMissingInternetExposure) {
			log.Warn("scan blocked: missing exposure classification")
			return fmt.Errorf("%w: %s", asynq.SkipRetry, err.Error())
		}
		return fmt.Errorf("verify scan eligibility: %w", err)
	}
	if row.GithubInstallationID == nil {
		return fmt.Errorf("org %s has no GitHub App installation", row.GithubOrgLogin)
	}

	parts := strings.SplitN(row.FullName, "/", 2)
	if len(parts) != 2 {
		return fmt.Errorf("invalid full_name: %s", row.FullName)
	}
	owner, repoName := parts[0], parts[1]

	// --- 2. Resolve or create scan_job record ---
	now := time.Now()
	jobID, err := h.resolveScanJobID(ctx, repoID, payload.JobID, payload.Trigger, now)
	if err != nil {
		if errors.Is(err, asynq.SkipRetry) {
			log.Info("duplicate scan task skipped", zap.Error(err))
			return nil
		}
		return fmt.Errorf("resolve scan_job: %w", err)
	}

	scanErr := h.runScan(ctx, jobID, repoID, row.OrgID, row.TenantID, owner, repoName,
		row.DefaultBranch, *row.GithubInstallationID, log)

	// --- Update scan_job status ---
	completedAt := time.Now()
	if scanErr != nil {
		errMsg := scanErr.Error()
		_, _ = h.db.Exec(ctx, `
			UPDATE scan_jobs SET status='failed', completed_at=$1, error_msg=$2 WHERE id=$3`,
			completedAt, errMsg, jobID,
		)
		return scanErr
	}

	_, _ = h.db.Exec(ctx, `
		UPDATE scan_jobs SET status='completed', completed_at=$1 WHERE id=$2`,
		completedAt, jobID,
	)
	_, _ = h.db.Exec(ctx, `
		UPDATE repositories SET last_scanned_at=$1 WHERE id=$2`,
		completedAt, repoID,
	)

	log.Info("scan completed")
	return nil
}

func (h *scanRepoHandler) resolveScanJobID(
	ctx context.Context,
	repoID uuid.UUID,
	payloadJobID, trigger string,
	now time.Time,
) (uuid.UUID, error) {
	if payloadJobID != "" {
		jobID, err := uuid.Parse(payloadJobID)
		if err != nil {
			return uuid.Nil, fmt.Errorf("parse job_id: %w", err)
		}
		if err := h.failIfAnotherScanRunning(ctx, repoID, jobID, now); err != nil {
			return uuid.Nil, err
		}
		tag, err := h.db.Exec(ctx, `
			UPDATE scan_jobs
			SET status = 'running', started_at = COALESCE(started_at, $1)
			WHERE id = $2 AND repo_id = $3 AND status IN ('pending', 'running')`,
			now, jobID, repoID,
		)
		if err != nil {
			return uuid.Nil, err
		}
		if tag.RowsAffected() > 0 {
			return jobID, nil
		}
	}

	var pendingID uuid.UUID
	err := h.db.QueryRow(ctx, `
		SELECT id FROM scan_jobs
		WHERE repo_id = $1 AND status = 'pending'
		ORDER BY created_at DESC
		LIMIT 1`, repoID,
	).Scan(&pendingID)
	if err == nil {
		if err := h.failIfAnotherScanRunning(ctx, repoID, pendingID, now); err != nil {
			return uuid.Nil, err
		}
		_, err = h.db.Exec(ctx, `
			UPDATE scan_jobs SET status = 'running', started_at = $1 WHERE id = $2`,
			now, pendingID,
		)
		if err != nil {
			return uuid.Nil, err
		}
		return pendingID, nil
	}

	if err := h.failIfAnotherScanRunning(ctx, repoID, uuid.Nil, now); err != nil {
		return uuid.Nil, err
	}

	jobID := uuid.New()
	_, err = h.db.Exec(ctx, `
		INSERT INTO scan_jobs (id, repo_id, status, triggered_by, started_at, created_at)
		VALUES ($1, $2, 'running', $3, $4, $4)`,
		jobID, repoID, trigger, now,
	)
	if err != nil {
		if repositoriesvc.IsActiveScanUniqueViolation(err) {
			return uuid.Nil, h.supersedeDuplicateJob(ctx, repoID, uuid.Nil, now)
		}
		return uuid.Nil, err
	}
	return jobID, nil
}

func (h *scanRepoHandler) failIfAnotherScanRunning(
	ctx context.Context,
	repoID, currentJobID uuid.UUID,
	now time.Time,
) error {
	var runningID uuid.UUID
	var err error
	if currentJobID == uuid.Nil {
		err = h.db.QueryRow(ctx, `
			SELECT id FROM scan_jobs
			WHERE repo_id = $1 AND status = 'running'
			LIMIT 1`, repoID,
		).Scan(&runningID)
	} else {
		err = h.db.QueryRow(ctx, `
			SELECT id FROM scan_jobs
			WHERE repo_id = $1 AND status = 'running' AND id <> $2
			LIMIT 1`, repoID, currentJobID,
		).Scan(&runningID)
	}
	if err != nil {
		return nil
	}
	return h.supersedeDuplicateJob(ctx, repoID, currentJobID, now)
}

func (h *scanRepoHandler) supersedeDuplicateJob(
	ctx context.Context,
	repoID uuid.UUID,
	jobID uuid.UUID,
	now time.Time,
) error {
	if jobID != uuid.Nil {
		_, _ = h.db.Exec(ctx, `
			UPDATE scan_jobs
			SET status = 'failed', completed_at = $1, error_msg = $2
			WHERE id = $3 AND repo_id = $4 AND status IN ('pending', 'running')`,
			now, "superseded: scan already queued or running", jobID, repoID,
		)
	}
	return fmt.Errorf("%w: scan already running for repo", asynq.SkipRetry)
}

func (h *scanRepoHandler) runScan(
	ctx context.Context,
	jobID, repoID, orgID, tenantID uuid.UUID,
	owner, repoName, branch string,
	installationID int64,
	log *zap.Logger,
) error {
	// --- 3. Shallow clone ---
	workDir := filepath.Join(os.TempDir(), "scan-workdir")
	cloneDir, err := h.github.CloneRepo(ctx, tenantID, installationID, owner, repoName, branch, workDir)
	if err != nil {
		return fmt.Errorf("clone: %w", err)
	}
	defer func() { _ = os.RemoveAll(cloneDir) }()

	log.Info("cloned repo", zap.String("dir", cloneDir))

	// --- 4. Detect manifests (monorepo aware) ---
	manifests, err := scanner.FindManifests(cloneDir)
	if err != nil {
		return fmt.Errorf("find manifests: %w", err)
	}

	isMonorepo := scanner.IsMonorepo(manifests)
	_, _ = h.db.Exec(ctx, `UPDATE repositories SET is_monorepo=$1 WHERE id=$2`, isMonorepo, repoID)

	log.Info("found manifests", zap.Int("count", len(manifests)), zap.Bool("monorepo", isMonorepo))

	// --- 5. Read CODEOWNERS ---
	coContent, err := h.github.GetCODEOWNERS(ctx, tenantID, installationID, owner, repoName, branch)
	if err != nil {
		log.Warn("could not fetch CODEOWNERS", zap.Error(err))
	}
	coRuleset, err := codeowners.Parse(coContent)
	if err != nil {
		log.Warn("could not parse CODEOWNERS", zap.Error(err))
		coRuleset, _ = codeowners.Parse("")
	}

	// --- 6. Upsert manifests & run OSV scanner per manifest ---
	for _, m := range manifests {
		manifestID, err := h.upsertManifest(ctx, repoID, m)
		if err != nil {
			log.Warn("upsert manifest failed", zap.String("path", m.Path), zap.Error(err))
			continue
		}

		if h.cfg.MaliciousDatasetEnabled {
			dependencies, depErr := scanner.ParseManifestDependencies(m)
			if depErr != nil && !errors.Is(depErr, scanner.ErrGuardDogUnsupportedManifest) {
				log.Warn("parse manifest dependencies for malicious dataset failed", zap.String("path", m.Path), zap.Error(depErr))
			}
			for _, dep := range dependencies {
				inventoryID, invErr := h.upsertPackageInventory(
					ctx,
					tenantID,
					repoID,
					manifestID,
					nil,
					m.Ecosystem,
					dep.Name,
					dep.Version,
				)
				if invErr != nil {
					log.Warn("upsert package inventory for manifest dependency failed",
						zap.String("path", m.Path),
						zap.String("package_name", dep.Name),
						zap.String("package_version", dep.Version),
						zap.Error(invErr),
					)
					continue
				}
				if err := h.detectKnownMaliciousPackageForPackage(
					ctx,
					tenantID,
					repoID,
					jobID,
					manifestID,
					inventoryID,
					nil,
					dep.Name,
					dep.Version,
					m.Ecosystem,
					log,
				); err != nil {
					log.Warn("malicious dataset match for manifest dependency failed",
						zap.String("path", m.Path),
						zap.String("package_name", dep.Name),
						zap.String("package_version", dep.Version),
						zap.Error(err),
					)
				}
			}
		}

		findings, err := scanner.ScanManifest(ctx, m)
		if err != nil {
			log.Warn("scan manifest failed", zap.String("path", m.Path), zap.Error(err))
			continue
		}

		log.Info("manifest scanned", zap.String("path", m.Path), zap.Int("findings", len(findings)))

		if h.cfg.GuardDogEnabled && scanner.SupportsGuardDogManifest(m) {
			signals, err := scanner.ScanManifestGuardDog(ctx, m, scanner.GuardDogOptions{
				BinaryPath: h.cfg.GuardDogBinary,
				Timeout:    time.Duration(h.cfg.GuardDogTimeoutS) * time.Second,
			})
			if err != nil {
				log.Warn("guarddog scan failed", zap.String("path", m.Path), zap.Error(err))
			} else {
				log.Info("guarddog scan completed", zap.String("path", m.Path), zap.Int("signals", len(signals)))
				for _, signal := range signals {
					inventoryID, err := h.upsertPackageInventory(
						ctx,
						tenantID,
						repoID,
						manifestID,
						nil,
						signal.Ecosystem,
						signal.PackageName,
						signal.PackageVersion,
					)
					if err != nil {
						log.Warn("upsert package inventory for guarddog failed", zap.String("path", m.Path), zap.Error(err))
					}

					signalID, err := h.upsertSupplyChainSignal(ctx, supplyChainSignalInput{
						TenantID:           tenantID,
						RepoID:             &repoID,
						ScanJobID:          &jobID,
						ManifestID:         &manifestID,
						PackageInventoryID: inventoryID,
						IndicatorID:        nil,
						SignalType:         models.SignalTypeSuspiciousBehavior,
						Status:             models.SignalStatusOpen,
						Severity:           signal.Severity,
						PackageEcosystem:   signal.Ecosystem,
						PackageName:        signal.PackageName,
						PackageVersion:     signal.PackageVersion,
						SourceEngine:       "guarddog",
						SignalKey:          signal.SignalKey,
						Reasoning:          "guarddog heuristic matched suspicious behavior",
						EvidenceJSON:       signal.EvidenceJSON,
						MetadataJSON:       signal.EvidenceJSON,
						Confidence:         signal.Confidence,
					})
					if err != nil {
						if isMissingGuardDogSchema(err) {
							log.Warn("guarddog signal schema unavailable", zap.Error(err))
							break
						}
						log.Warn("upsert guarddog signal failed", zap.String("path", m.Path), zap.Error(err))
					}

					if signal.Severity != models.SeverityHigh && signal.Severity != models.SeverityCritical {
						continue
					}
					findingID, err := h.upsertSuspiciousBehaviorFinding(ctx, tenantID, jobID, manifestID, signal)
					if err != nil {
						log.Warn("upsert suspicious behavior finding failed", zap.String("path", m.Path), zap.Error(err))
						continue
					}
					if signalID != nil {
						if err := h.attachFindingToSignal(ctx, *signalID, findingID); err != nil {
							log.Warn("attach finding to guarddog signal failed", zap.String("path", m.Path), zap.Error(err))
						}
					}

					if !h.cfg.PackageDynamicAnalysisEnabled {
						continue
					}
					err = h.enqueuer.EnqueuePackageDynamicAnalysisFromSignal(
						tenantID,
						signal.Ecosystem,
						signal.PackageName,
						signal.PackageVersion,
						signal.Severity,
						signalID,
					)
					if err != nil && !errors.Is(err, asynq.ErrDuplicateTask) && !errors.Is(err, asynq.ErrTaskIDConflict) {
						log.Warn("enqueue package dynamic analysis from guarddog signal failed",
							zap.String("path", m.Path),
							zap.Error(err),
						)
					}
				}
			}
		}

		// --- 7. Persist findings ---
		for i := range findings {
			findings[i].TenantID = tenantID
			findings[i].ScanJobID = &jobID
			findings[i].ManifestID = &manifestID
			if err := h.upsertFinding(ctx, &findings[i]); err != nil {
				log.Warn("upsert finding failed", zap.String("osv_id", findings[i].OSVID), zap.Error(err))
				continue
			}
			inventoryID, err := h.upsertPackageInventory(
				ctx,
				tenantID,
				repoID,
				manifestID,
				&findings[i].ID,
				m.Ecosystem,
				findings[i].PackageName,
				findings[i].PackageVersion,
			)
			if err != nil {
				log.Warn("upsert package inventory failed", zap.String("finding_id", findings[i].ID.String()), zap.Error(err))
			}

			if h.cfg.MaliciousDatasetEnabled {
				if err := h.detectKnownMaliciousPackageForPackage(
					ctx,
					tenantID,
					repoID,
					jobID,
					manifestID,
					inventoryID,
					&findings[i].ID,
					findings[i].PackageName,
					findings[i].PackageVersion,
					m.Ecosystem,
					log,
				); err != nil {
					log.Warn("malicious dataset match failed", zap.String("finding_id", findings[i].ID.String()), zap.Error(err))
				}
			}

			if err := h.prioritization.ApplyReachability(ctx, findings[i].ID, cloneDir, m, findings[i].PackageName); err != nil {
				log.Warn("reachability analysis failed", zap.String("finding_id", findings[i].ID.String()), zap.Error(err))
			}
			if err := h.prioritization.RecalculateRiskScore(ctx, findings[i].ID, tenantID); err != nil {
				log.Warn("risk score calculation failed", zap.String("finding_id", findings[i].ID.String()), zap.Error(err))
			}

			EnqueueFindingAnalysisAfterUpsert(ctx, h.enqueuer, h.analysis, findings[i].ID, tenantID, jobID, log)

			// --- 8. Map to teams via CODEOWNERS ---
			owners := coRuleset.OwnersForPath(m.Path)
			for _, owner := range codeowners.TeamsFromOwners(owners) {
				teamID, err := h.upsertTeam(ctx, orgID, owner)
				if err != nil {
					log.Warn("upsert team failed", zap.String("team", owner.Raw), zap.Error(err))
					continue
				}
				_, _ = h.db.Exec(ctx, `
					INSERT INTO finding_teams (finding_id, team_id, codeowners_pattern)
					VALUES ($1, $2, $3)
					ON CONFLICT DO NOTHING`,
					findings[i].ID, teamID, m.Path,
				)
			}
		}
	}

	return nil
}

func (h *scanRepoHandler) upsertManifest(ctx context.Context, repoID uuid.UUID, m scanner.Manifest) (uuid.UUID, error) {
	var id uuid.UUID
	err := h.db.QueryRow(ctx, `
		INSERT INTO manifests (id, repo_id, path, ecosystem, created_at)
		VALUES ($1, $2, $3, $4, NOW())
		ON CONFLICT (repo_id, path) DO UPDATE SET ecosystem = EXCLUDED.ecosystem
		RETURNING id`,
		uuid.New(), repoID, m.Path, m.Ecosystem,
	).Scan(&id)
	return id, err
}

func (h *scanRepoHandler) upsertFinding(ctx context.Context, f *models.Finding) error {
	if f.TenantID == uuid.Nil {
		h.log.Error("finding upsert blocked: tenant_id is required",
			zap.String("finding_id", f.ID.String()),
			zap.String("osv_id", f.OSVID),
			zap.String("package_name", f.PackageName),
			zap.String("package_version", f.PackageVersion),
		)
		return fmt.Errorf("finding upsert blocked: tenant_id is required (osv_id=%s)", f.OSVID)
	}

	// The unique index (manifest_id, osv_id, package_name, package_version)
	// lets us refresh metadata (severity, fixed_version, summary, scan_job_id)
	// on every rescan without duplicating rows. status is preserved so that
	// "suppressed"/"fixed" decisions survive rescans.
	err := h.db.QueryRow(ctx, `
		INSERT INTO findings
			(id, tenant_id, scan_job_id, manifest_id, osv_id, package_name, package_version,
			 fixed_version, severity, cvss_score, summary, details, status,
			 first_seen_at, last_seen_at)
		VALUES
			($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,NOW(),NOW())
		ON CONFLICT (manifest_id, osv_id, package_name, package_version)
		DO UPDATE SET
			scan_job_id   = EXCLUDED.scan_job_id,
			tenant_id     = EXCLUDED.tenant_id,
			fixed_version = EXCLUDED.fixed_version,
			severity      = EXCLUDED.severity,
			cvss_score    = EXCLUDED.cvss_score,
			summary       = EXCLUDED.summary,
			details       = EXCLUDED.details,
			last_seen_at  = NOW()
		RETURNING id`,
		f.ID, f.TenantID, f.ScanJobID, f.ManifestID, f.OSVID, f.PackageName, f.PackageVersion,
		f.FixedVersion, f.Severity, f.CVSSScore, f.Summary, f.Details, f.Status,
	).Scan(&f.ID)
	return err
}

func (h *scanRepoHandler) upsertTeam(ctx context.Context, orgID uuid.UUID, owner codeowners.Owner) (uuid.UUID, error) {
	displayName := owner.TeamSlug
	if displayName == "" {
		displayName = owner.Username
	}

	var id uuid.UUID
	err := h.db.QueryRow(ctx, `
		INSERT INTO teams (id, org_id, github_team_slug, display_name, created_at)
		VALUES ($1, $2, $3, $4, NOW())
		ON CONFLICT (org_id, github_team_slug) DO UPDATE SET display_name = EXCLUDED.display_name
		RETURNING id`,
		uuid.New(), orgID, owner.TeamSlug, displayName,
	).Scan(&id)
	return id, err
}

type supplyChainSignalInput struct {
	TenantID           uuid.UUID
	RepoID             *uuid.UUID
	ScanJobID          *uuid.UUID
	ManifestID         *uuid.UUID
	PackageInventoryID *uuid.UUID
	FindingID          *uuid.UUID
	IndicatorID        *uuid.UUID
	SignalType         models.SupplyChainSignalType
	Status             models.SupplyChainSignalStatus
	Severity           models.Severity
	PackageEcosystem   string
	PackageName        string
	PackageVersion     string
	SourceEngine       string
	SignalKey          string
	Reasoning          string
	EvidenceJSON       []byte
	MetadataJSON       []byte
	Confidence         *float64
}

func (h *scanRepoHandler) upsertSupplyChainSignal(ctx context.Context, input supplyChainSignalInput) (*uuid.UUID, error) {
	evidenceJSON := normalizeJSONB(input.EvidenceJSON)
	metadataJSON := normalizeJSONB(input.MetadataJSON)
	signalHash := hashSupplyChainSignal(
		input.TenantID.String(),
		stringOrNil(input.RepoID),
		stringOrNil(input.ManifestID),
		strings.ToLower(strings.TrimSpace(input.SourceEngine)),
		strings.ToLower(strings.TrimSpace(string(input.SignalType))),
		strings.ToLower(strings.TrimSpace(input.PackageEcosystem)),
		strings.ToLower(strings.TrimSpace(input.PackageName)),
		strings.TrimSpace(input.PackageVersion),
		strings.ToLower(strings.TrimSpace(input.SignalKey)),
	)
	var signalID uuid.UUID
	err := h.db.QueryRow(ctx, `
		INSERT INTO supply_chain_signals
			(id, tenant_id, scan_job_id, repo_id, manifest_id, package_inventory_id, finding_id, indicator_id,
			 signal_type, status, severity, package_ecosystem, package_name, package_version, source_engine,
			 signal_key, signal_hash, confidence, reasoning, evidence_json, metadata_json,
			 first_seen_at, last_seen_at, created_at, updated_at)
		VALUES
			($1, $2, $3, $4, $5, $6, $7, $8,
			 $9, $10, $11, $12, $13, $14, $15,
			 $16, $17, $18, $19, $20::jsonb, $21::jsonb,
			 NOW(), NOW(), NOW(), NOW())
		ON CONFLICT (tenant_id, signal_hash)
		DO UPDATE SET
			scan_job_id = COALESCE(EXCLUDED.scan_job_id, supply_chain_signals.scan_job_id),
			repo_id = COALESCE(EXCLUDED.repo_id, supply_chain_signals.repo_id),
			manifest_id = COALESCE(EXCLUDED.manifest_id, supply_chain_signals.manifest_id),
			package_inventory_id = COALESCE(EXCLUDED.package_inventory_id, supply_chain_signals.package_inventory_id),
			finding_id = COALESCE(EXCLUDED.finding_id, supply_chain_signals.finding_id),
			indicator_id = COALESCE(EXCLUDED.indicator_id, supply_chain_signals.indicator_id),
			status = CASE
				WHEN supply_chain_signals.status IN ('resolved', 'suppressed', 'triaged') THEN supply_chain_signals.status
				ELSE EXCLUDED.status
			END,
			severity = EXCLUDED.severity,
			confidence = EXCLUDED.confidence,
			reasoning = EXCLUDED.reasoning,
			evidence_json = EXCLUDED.evidence_json,
			metadata_json = EXCLUDED.metadata_json,
			last_seen_at = NOW(),
			updated_at = NOW()
		RETURNING id`,
		uuid.New(),
		input.TenantID,
		input.ScanJobID,
		input.RepoID,
		input.ManifestID,
		input.PackageInventoryID,
		input.FindingID,
		input.IndicatorID,
		input.SignalType,
		input.Status,
		input.Severity,
		strings.TrimSpace(input.PackageEcosystem),
		strings.TrimSpace(input.PackageName),
		strings.TrimSpace(input.PackageVersion),
		strings.TrimSpace(input.SourceEngine),
		strings.TrimSpace(input.SignalKey),
		signalHash,
		input.Confidence,
		input.Reasoning,
		string(evidenceJSON),
		string(metadataJSON),
	).Scan(&signalID)
	if err != nil {
		return nil, err
	}
	return &signalID, nil
}

func (h *scanRepoHandler) upsertPackageInventory(
	ctx context.Context,
	tenantID, repoID, manifestID uuid.UUID,
	findingID *uuid.UUID,
	ecosystem, packageName, packageVersion string,
) (*uuid.UUID, error) {
	var inventoryID uuid.UUID
	err := h.db.QueryRow(ctx, `
		INSERT INTO package_inventory
			(id, tenant_id, repo_id, manifest_id, finding_id, ecosystem, package_name, package_version,
			 dependency_scope, source, first_seen_at, last_seen_at, created_at, updated_at)
		VALUES
			($1, $2, $3, $4, $5, $6, $7, $8, 'unknown', 'scan', NOW(), NOW(), NOW(), NOW())
		ON CONFLICT (tenant_id, repo_id, ecosystem, package_name, package_version)
		DO UPDATE SET
			manifest_id = COALESCE(EXCLUDED.manifest_id, package_inventory.manifest_id),
			finding_id = COALESCE(EXCLUDED.finding_id, package_inventory.finding_id),
			last_seen_at = NOW(),
			updated_at = NOW()
		RETURNING id`,
		uuid.New(), tenantID, repoID, manifestID, findingID,
		strings.TrimSpace(ecosystem), strings.TrimSpace(packageName), strings.TrimSpace(packageVersion),
	).Scan(&inventoryID)
	if err != nil {
		return nil, err
	}
	return &inventoryID, nil
}

type matchedIndicator struct {
	ID         uuid.UUID
	ExternalID string
	Summary    string
	Details    string
}

func matchesKnownMaliciousIndicator(
	lookupEcosystem, lookupPackageName, lookupPackageVersion string,
	indicatorEcosystem, indicatorPackageName, indicatorPackageVersion string,
) bool {
	if !strings.EqualFold(strings.TrimSpace(lookupEcosystem), strings.TrimSpace(indicatorEcosystem)) {
		return false
	}
	if !strings.EqualFold(strings.TrimSpace(lookupPackageName), strings.TrimSpace(indicatorPackageName)) {
		return false
	}
	normalizedLookupVersion := strings.TrimSpace(lookupPackageVersion)
	normalizedIndicatorVersion := strings.TrimSpace(indicatorPackageVersion)
	return normalizedIndicatorVersion == "" || normalizedIndicatorVersion == normalizedLookupVersion
}

func knownMaliciousVersionPriority(lookupVersion, indicatorVersion string) int {
	normalizedLookupVersion := strings.TrimSpace(lookupVersion)
	normalizedIndicatorVersion := strings.TrimSpace(indicatorVersion)
	switch {
	case normalizedIndicatorVersion == normalizedLookupVersion && normalizedIndicatorVersion != "":
		return 0
	case normalizedIndicatorVersion == "":
		return 1
	default:
		return 2
	}
}

func preserveSignalStatusOnConflict(
	existingStatus models.SupplyChainSignalStatus,
	incomingStatus models.SupplyChainSignalStatus,
) models.SupplyChainSignalStatus {
	switch existingStatus {
	case models.SignalStatusResolved, models.SignalStatusSuppressed, models.SignalStatusTriaged:
		return existingStatus
	default:
		return incomingStatus
	}
}

func (h *scanRepoHandler) findKnownMaliciousIndicator(
	ctx context.Context,
	ecosystem, packageName, packageVersion string,
) (*matchedIndicator, error) {
	rows, err := h.db.Query(ctx, `
		SELECT id, external_id, summary, details, ecosystem, package_name, package_version
		FROM malicious_package_indicators
		WHERE withdrawn_at IS NULL
		  AND LOWER(package_name) = LOWER($1)
		  AND (package_version = '' OR package_version = $2)
		  AND LOWER(ecosystem) = LOWER($3)`,
		packageName,
		packageVersion,
		ecosystem,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var (
		best         *matchedIndicator
		bestPriority = 3
	)
	for rows.Next() {
		var (
			indicator          matchedIndicator
			indicatorEcosystem string
			indicatorName      string
			indicatorVersion   string
		)
		if err := rows.Scan(
			&indicator.ID,
			&indicator.ExternalID,
			&indicator.Summary,
			&indicator.Details,
			&indicatorEcosystem,
			&indicatorName,
			&indicatorVersion,
		); err != nil {
			return nil, err
		}

		if !matchesKnownMaliciousIndicator(
			ecosystem,
			packageName,
			packageVersion,
			indicatorEcosystem,
			indicatorName,
			indicatorVersion,
		) {
			continue
		}

		priority := knownMaliciousVersionPriority(packageVersion, indicatorVersion)
		if priority > 1 {
			continue
		}
		if best == nil || priority < bestPriority {
			copyIndicator := indicator
			best = &copyIndicator
			bestPriority = priority
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if best == nil {
		return nil, pgx.ErrNoRows
	}
	return best, nil
}

func (h *scanRepoHandler) detectKnownMaliciousPackageForPackage(
	ctx context.Context,
	tenantID, repoID, jobID, manifestID uuid.UUID,
	inventoryID *uuid.UUID,
	existingFindingID *uuid.UUID,
	packageName, packageVersion string,
	ecosystem string,
	log *zap.Logger,
) error {
	indicator, err := h.findKnownMaliciousIndicator(ctx, ecosystem, packageName, packageVersion)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		return err
	}
	indicatorID := indicator.ID
	datasetEvidenceJSON, _ := json.Marshal(map[string]any{
		"external_id": indicator.ExternalID,
		"summary":     indicator.Summary,
		"details":     indicator.Details,
		"source":      "openssf-malicious-packages",
	})
	signalID, err := h.upsertSupplyChainSignal(ctx, supplyChainSignalInput{
		TenantID:           tenantID,
		RepoID:             &repoID,
		ScanJobID:          &jobID,
		ManifestID:         &manifestID,
		PackageInventoryID: inventoryID,
		FindingID:          existingFindingID,
		IndicatorID:        &indicatorID,
		SignalType:         models.SignalTypeMaliciousPackage,
		Status:             models.SignalStatusOpen,
		Severity:           models.SeverityCritical,
		PackageEcosystem:   ecosystem,
		PackageName:        packageName,
		PackageVersion:     packageVersion,
		SourceEngine:       "dataset",
		SignalKey:          indicator.ExternalID,
		Reasoning:          "package matched OpenSSF malicious package dataset",
		EvidenceJSON:       datasetEvidenceJSON,
		MetadataJSON:       datasetEvidenceJSON,
		Confidence:         nil,
	})
	if err != nil {
		return err
	}

	maliciousFinding := models.Finding{
		ID:             uuid.New(),
		TenantID:       tenantID,
		ScanJobID:      &jobID,
		ManifestID:     &manifestID,
		OSVID:          indicator.ExternalID,
		PackageName:    packageName,
		PackageVersion: packageVersion,
		Severity:       models.SeverityCritical,
		Summary:        coalesceText(indicator.Summary, "Known malicious package detected"),
		Details:        coalesceText(indicator.Details, "Package matched known malicious indicator dataset"),
		Status:         models.FindingOpen,
	}
	if err := h.upsertFinding(ctx, &maliciousFinding); err != nil {
		return err
	}
	_, err = h.db.Exec(ctx, `
		UPDATE findings
		SET finding_type='malicious_package', source_engine='dataset'
		WHERE id=$1`,
		maliciousFinding.ID,
	)
	if err != nil {
		if isMissingGuardDogSchema(err) {
			return nil
		}
		return err
	}
	if signalID != nil {
		if err := h.attachFindingToSignal(ctx, *signalID, maliciousFinding.ID); err != nil {
			return err
		}
	}

	if h.cfg.PackageDynamicAnalysisEnabled {
		err = h.enqueuer.EnqueuePackageDynamicAnalysisFromSignal(
			tenantID,
			ecosystem,
			packageName,
			packageVersion,
			models.SeverityCritical,
			signalID,
		)
		if err != nil && !errors.Is(err, asynq.ErrDuplicateTask) && !errors.Is(err, asynq.ErrTaskIDConflict) {
			log.Warn("enqueue package dynamic analysis from malicious indicator failed",
				zap.String("package_name", packageName),
				zap.String("package_version", packageVersion),
				zap.Error(err),
			)
		}
	}
	return nil
}

func (h *scanRepoHandler) upsertSuspiciousBehaviorFinding(
	ctx context.Context,
	tenantID, jobID, manifestID uuid.UUID,
	signal scanner.SupplyChainSignal,
) (uuid.UUID, error) {
	details := string(signal.EvidenceJSON)
	if details == "" {
		details = "{}"
	}

	finding := models.Finding{
		ID:             uuid.New(),
		TenantID:       tenantID,
		ScanJobID:      &jobID,
		ManifestID:     &manifestID,
		OSVID:          "guarddog:" + signal.SignalKey,
		PackageName:    signal.PackageName,
		PackageVersion: signal.PackageVersion,
		Severity:       signal.Severity,
		Summary:        "GuardDog suspicious package behavior detected",
		Details:        details,
		Status:         models.FindingOpen,
	}
	if err := h.upsertFinding(ctx, &finding); err != nil {
		return uuid.Nil, err
	}

	_, err := h.db.Exec(ctx, `
		UPDATE findings
		SET finding_type='suspicious_behavior', source_engine='guarddog'
		WHERE id=$1`,
		finding.ID,
	)
	if err != nil && !isMissingGuardDogSchema(err) {
		return uuid.Nil, err
	}
	return finding.ID, nil
}

func (h *scanRepoHandler) attachFindingToSignal(ctx context.Context, signalID, findingID uuid.UUID) error {
	_, err := h.db.Exec(ctx, `
		UPDATE supply_chain_signals
		SET finding_id = COALESCE(finding_id, $1),
		    updated_at = NOW()
		WHERE id = $2`,
		findingID, signalID,
	)
	return err
}

func isMissingGuardDogSchema(err error) bool {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		return pgErr.Code == "42P01" || pgErr.Code == "42703"
	}
	return false
}

func normalizeJSONB(raw []byte) []byte {
	trimmed := strings.TrimSpace(string(raw))
	if trimmed == "" {
		return []byte("{}")
	}
	return []byte(trimmed)
}

func stringOrNil(value *uuid.UUID) string {
	if value == nil {
		return ""
	}
	return value.String()
}

func hashSupplyChainSignal(parts ...string) string {
	normalized := strings.Join(parts, "|")
	sum := sha256.Sum256([]byte(normalized))
	return hex.EncodeToString(sum[:])
}

func coalesceText(value, fallback string) string {
	trimmed := strings.TrimSpace(value)
	if trimmed != "" {
		return trimmed
	}
	return fallback
}
