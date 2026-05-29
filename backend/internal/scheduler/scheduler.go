package scheduler

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/go-co-op/gocron/v2"
	"github.com/google/uuid"
	"github.com/hibiken/asynq"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/purplehatlabs/Baldr/internal/models"
	"github.com/purplehatlabs/Baldr/internal/queue"
	repositoriesvc "github.com/purplehatlabs/Baldr/internal/repositories"
	"go.uber.org/zap"
)

const metricsSnapshotCronExpr = "15 0 * * *"
const exceptionExpiryCronExpr = "30 1 * * *"
const riskEnrichmentCronExpr = "0 3 * * *"
const maliciousDatasetSyncCronExpr = "30 3 * * *"
const membershipSyncCronExpr = "0 4 * * *"

// OrgScheduler manages per-organization cron scan schedules.
type OrgScheduler struct {
	scheduler gocron.Scheduler
	client    *asynq.Client
	db        *pgxpool.Pool
	log       *zap.Logger

	membershipSyncEnabled bool

	mu   sync.Mutex
	jobs map[uuid.UUID]gocron.Job // orgID → job

	metricsJob          gocron.Job
	exceptionJob        gocron.Job
	riskEnrichmentJob   gocron.Job
	maliciousDatasetJob gocron.Job
	membershipSyncJob   gocron.Job
}

func New(redisOpt asynq.RedisConnOpt, db *pgxpool.Pool, log *zap.Logger, membershipSyncEnabled bool) (*OrgScheduler, error) {
	s, err := gocron.NewScheduler()
	if err != nil {
		return nil, fmt.Errorf("create scheduler: %w", err)
	}

	return &OrgScheduler{
		scheduler:             s,
		client:                asynq.NewClient(redisOpt),
		db:                    db,
		log:                   log,
		membershipSyncEnabled: membershipSyncEnabled,
		jobs:                  make(map[uuid.UUID]gocron.Job),
	}, nil
}

// StartCron launches cron scheduling and org sync loops. Call only on the elected leader.
func (s *OrgScheduler) StartCron(ctx context.Context) {
	s.scheduler.Start()
	s.registerMetricsSnapshotJob()
	s.registerExceptionExpiryJob()
	s.registerRiskEnrichmentJob()
	s.registerMaliciousDatasetSyncJob()
	if s.membershipSyncEnabled {
		s.registerMembershipSyncJob()
	}
	s.sync(ctx)

	go func() {
		ticker := time.NewTicker(5 * time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				s.sync(ctx)
			case <-ctx.Done():
				return
			}
		}
	}()
}

// StopCron stops cron scheduling without closing the asynq client used for manual enqueues.
func (s *OrgScheduler) StopCron() {
	_ = s.scheduler.Shutdown()
}

// Start launches the scheduler and syncs org crons every 5 minutes.
// Deprecated: prefer StartCron behind leader election.
func (s *OrgScheduler) Start(ctx context.Context) {
	s.StartCron(ctx)
}

func (s *OrgScheduler) registerMetricsSnapshotJob() {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.metricsJob != nil {
		return
	}

	job, err := s.scheduler.NewJob(
		gocron.CronJob(metricsSnapshotCronExpr, false),
		gocron.NewTask(func() {
			s.enqueueDailyMetricsSnapshot(context.Background())
		}),
		gocron.WithName(queue.TaskMetricsSnapshotDaily),
	)
	if err != nil {
		s.log.Error("register metrics snapshot cron", zap.Error(err))
		return
	}

	s.metricsJob = job
	s.log.Info("registered metrics snapshot cron", zap.String("cron", metricsSnapshotCronExpr))
}

func (s *OrgScheduler) registerExceptionExpiryJob() {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.exceptionJob != nil {
		return
	}

	job, err := s.scheduler.NewJob(
		gocron.CronJob(exceptionExpiryCronExpr, false),
		gocron.NewTask(func() {
			s.enqueueExceptionExpiry(context.Background())
		}),
		gocron.WithName(queue.TaskExpireExceptions),
	)
	if err != nil {
		s.log.Error("register exception expiry cron", zap.Error(err))
		return
	}

	s.exceptionJob = job
	s.log.Info("registered exception expiry cron", zap.String("cron", exceptionExpiryCronExpr))
}

func (s *OrgScheduler) registerRiskEnrichmentJob() {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.riskEnrichmentJob != nil {
		return
	}

	job, err := s.scheduler.NewJob(
		gocron.CronJob(riskEnrichmentCronExpr, false),
		gocron.NewTask(func() {
			s.enqueueDailyRiskEnrichment(context.Background())
		}),
		gocron.WithName(queue.TaskThreatIntelDaily),
	)
	if err != nil {
		s.log.Error("register risk enrichment cron", zap.Error(err))
		return
	}

	s.riskEnrichmentJob = job
	s.log.Info("registered risk enrichment cron", zap.String("cron", riskEnrichmentCronExpr))
}

func (s *OrgScheduler) registerMaliciousDatasetSyncJob() {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.maliciousDatasetJob != nil {
		return
	}

	job, err := s.scheduler.NewJob(
		gocron.CronJob(maliciousDatasetSyncCronExpr, false),
		gocron.NewTask(func() {
			s.enqueueDailyMaliciousDatasetSync(context.Background())
		}),
		gocron.WithName(queue.TaskMaliciousDatasetSyncDaily),
	)
	if err != nil {
		s.log.Error("register malicious dataset cron", zap.Error(err))
		return
	}

	s.maliciousDatasetJob = job
	s.log.Info("registered malicious dataset cron", zap.String("cron", maliciousDatasetSyncCronExpr))
}

func (s *OrgScheduler) registerMembershipSyncJob() {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.membershipSyncJob != nil {
		return
	}

	job, err := s.scheduler.NewJob(
		gocron.CronJob(membershipSyncCronExpr, false),
		gocron.NewTask(func() {
			s.enqueueAllMembershipSyncs(context.Background())
		}),
		gocron.WithName(queue.TaskMembershipSync),
	)
	if err != nil {
		s.log.Error("register membership sync cron", zap.Error(err))
		return
	}

	s.membershipSyncJob = job
	s.log.Info("registered membership sync cron", zap.String("cron", membershipSyncCronExpr))
}

func (s *OrgScheduler) enqueueAllMembershipSyncs(ctx context.Context) {
	rows, err := s.db.Query(ctx, `
		SELECT id, tenant_id FROM organizations
		WHERE is_active = TRUE AND github_app_installation_id IS NOT NULL`)
	if err != nil {
		s.log.Error("load orgs for membership sync", zap.Error(err))
		return
	}
	defer rows.Close()

	for rows.Next() {
		var orgID, tenantID uuid.UUID
		if err := rows.Scan(&orgID, &tenantID); err != nil {
			continue
		}
		task, err := queue.NewMembershipSyncTask(orgID, tenantID)
		if err != nil {
			s.log.Warn("build membership sync task", zap.Error(err))
			continue
		}
		taskID := "membership-sync:" + orgID.String()
		_, err = s.client.Enqueue(task, asynq.TaskID(taskID), asynq.Unique(6*time.Hour))
		if err != nil {
			if !errors.Is(err, asynq.ErrDuplicateTask) && !errors.Is(err, asynq.ErrTaskIDConflict) {
				s.log.Warn("enqueue membership sync", zap.String("org_id", orgID.String()), zap.Error(err))
			}
			continue
		}
		s.log.Info("enqueued membership sync", zap.String("org_id", orgID.String()))
	}
}

// EnqueueMembershipSync enqueues a membership sync for a single org.
func (s *OrgScheduler) EnqueueMembershipSync(orgID, tenantID uuid.UUID) error {
	task, err := queue.NewMembershipSyncTask(orgID, tenantID)
	if err != nil {
		return err
	}
	taskID := "membership-sync:" + orgID.String()
	_, err = s.client.Enqueue(task, asynq.TaskID(taskID))
	return err
}

func (s *OrgScheduler) enqueueExceptionExpiry(ctx context.Context) {
	task, err := queue.NewExpireExceptionsTask(time.Now().UTC())
	if err != nil {
		s.log.Error("build exception expiry task", zap.Error(err))
		return
	}

	_, err = s.client.Enqueue(task, asynq.Unique(23*time.Hour))
	if err != nil {
		if errors.Is(err, asynq.ErrDuplicateTask) {
			return
		}
		s.log.Warn("enqueue exception expiry task", zap.Error(err))
		return
	}

	s.log.Info("enqueued exception expiry task")
}

func (s *OrgScheduler) enqueueDailyMetricsSnapshot(ctx context.Context) {
	snapshotDate := time.Now().UTC().AddDate(0, 0, -1)
	task, err := queue.NewMetricsSnapshotDailyTask(snapshotDate)
	if err != nil {
		s.log.Error("build metrics snapshot task", zap.Error(err))
		return
	}

	_, err = s.client.Enqueue(task, asynq.Unique(23*time.Hour))
	if err != nil {
		if errors.Is(err, asynq.ErrDuplicateTask) {
			s.log.Info("metrics snapshot already enqueued",
				zap.String("snapshot_date", snapshotDate.Format(time.DateOnly)),
			)
			return
		}
		s.log.Warn("enqueue metrics snapshot task",
			zap.String("snapshot_date", snapshotDate.Format(time.DateOnly)),
			zap.Error(err),
		)
		return
	}

	s.log.Info("enqueued metrics snapshot task",
		zap.String("snapshot_date", snapshotDate.Format(time.DateOnly)),
	)
}

func (s *OrgScheduler) enqueueDailyRiskEnrichment(ctx context.Context) {
	task, err := queue.NewThreatIntelDailyTask()
	if err != nil {
		s.log.Error("build risk enrichment task", zap.Error(err))
		return
	}

	_, err = s.client.Enqueue(task, asynq.Unique(23*time.Hour))
	if err != nil {
		if errors.Is(err, asynq.ErrDuplicateTask) {
			return
		}
		s.log.Warn("enqueue risk enrichment task", zap.Error(err))
		return
	}

	s.log.Info("enqueued risk enrichment task")
}

func (s *OrgScheduler) enqueueDailyMaliciousDatasetSync(ctx context.Context) {
	task, err := queue.NewMaliciousDatasetSyncDailyTask()
	if err != nil {
		s.log.Error("build malicious dataset task", zap.Error(err))
		return
	}

	_, err = s.client.Enqueue(task, asynq.Unique(23*time.Hour))
	if err != nil {
		if errors.Is(err, asynq.ErrDuplicateTask) {
			return
		}
		s.log.Warn("enqueue malicious dataset task", zap.Error(err))
		return
	}

	s.log.Info("enqueued malicious dataset task")
}

// Close releases the asynq client. Safe to call on process shutdown.
func (s *OrgScheduler) Close() {
	_ = s.client.Close()
}

func (s *OrgScheduler) Stop() {
	s.StopCron()
	s.Close()
}

// sync loads all active orgs from the DB and registers/updates their cron jobs.
func (s *OrgScheduler) sync(ctx context.Context) {
	rows, err := s.db.Query(ctx, `
		SELECT id, scan_cron FROM organizations WHERE is_active = TRUE`)
	if err != nil {
		s.log.Error("load orgs for scheduling", zap.Error(err))
		return
	}
	defer rows.Close()

	s.mu.Lock()
	defer s.mu.Unlock()

	seen := map[uuid.UUID]bool{}
	for rows.Next() {
		var org models.Organization
		if err := rows.Scan(&org.ID, &org.ScanCron); err != nil {
			continue
		}
		seen[org.ID] = true

		if _, exists := s.jobs[org.ID]; !exists {
			s.registerOrgJob(org.ID, org.ScanCron)
		}
	}

	// Remove jobs for orgs that are no longer active
	for orgID, job := range s.jobs {
		if !seen[orgID] {
			_ = s.scheduler.RemoveJob(job.ID())
			delete(s.jobs, orgID)
		}
	}
}

func (s *OrgScheduler) registerOrgJob(orgID uuid.UUID, cronExpr string) {
	job, err := s.scheduler.NewJob(
		gocron.CronJob(cronExpr, false),
		gocron.NewTask(func() {
			s.enqueueOrgRepos(context.Background(), orgID)
		}),
		gocron.WithName(orgID.String()),
	)
	if err != nil {
		s.log.Error("register cron job", zap.String("org_id", orgID.String()), zap.Error(err))
		return
	}
	s.jobs[orgID] = job
	s.log.Info("registered cron", zap.String("org_id", orgID.String()), zap.String("cron", cronExpr))
}

// enqueueOrgRepos enqueues a scan job for every active repo in the org.
func (s *OrgScheduler) enqueueOrgRepos(ctx context.Context, orgID uuid.UUID) {
	rows, err := s.db.Query(ctx, `
		SELECT id FROM repositories
		WHERE org_id = $1 AND is_archived = FALSE`, orgID)
	if err != nil {
		s.log.Error("list repos for org", zap.String("org_id", orgID.String()), zap.Error(err))
		return
	}
	defer rows.Close()

	for rows.Next() {
		var repoID uuid.UUID
		if err := rows.Scan(&repoID); err != nil {
			continue
		}
		if err := repositoriesvc.EnsureRepoScannable(ctx, s.db, repoID); err != nil {
			if errors.Is(err, repositoriesvc.ErrScanBlockedMissingInternetExposure) {
				continue
			}
			s.log.Warn("check scan eligibility failed", zap.String("repo_id", repoID.String()), zap.Error(err))
			continue
		}
		if err := s.enqueueScan(repoID, models.TriggerScheduled); err != nil {
			if errors.Is(err, repositoriesvc.ErrScanAlreadyQueuedOrRunning) {
				continue
			}
			s.log.Warn("enqueue scan task", zap.String("repo_id", repoID.String()), zap.Error(err))
		}
	}
}

// EnqueueRepo manually enqueues a scan for a single repo (used by the API).
func (s *OrgScheduler) EnqueueRepo(repoID uuid.UUID, trigger models.ScanTrigger) error {
	if err := repositoriesvc.EnsureRepoScannable(context.Background(), s.db, repoID); err != nil {
		return err
	}
	return s.enqueueScan(repoID, trigger)
}

func scanTaskID(repoID uuid.UUID) string {
	return "scan:repo:" + repoID.String()
}

// enqueueScan creates a pending scan_jobs row and enqueues the worker task.
// Idempotent per repo: one pending/running job at a time (DB check + partial
// unique index), with asynq TaskID per repo as a queue-level backstop.
func (s *OrgScheduler) enqueueScan(repoID uuid.UUID, trigger models.ScanTrigger) error {
	ctx := context.Background()

	active, err := repositoriesvc.HasActiveScanJob(ctx, s.db, repoID)
	if err != nil {
		return fmt.Errorf("check active scan: %w", err)
	}
	if active {
		return repositoriesvc.ErrScanAlreadyQueuedOrRunning
	}

	jobID := uuid.New()
	_, err = s.db.Exec(ctx, `
		INSERT INTO scan_jobs (id, repo_id, status, triggered_by, created_at)
		VALUES ($1, $2, 'pending', $3, NOW())`,
		jobID, repoID, trigger,
	)
	if err != nil {
		if repositoriesvc.IsActiveScanUniqueViolation(err) {
			return repositoriesvc.ErrScanAlreadyQueuedOrRunning
		}
		return fmt.Errorf("create pending scan job: %w", err)
	}

	task, err := queue.NewScanRepoTask(repoID.String(), string(trigger), jobID.String())
	if err != nil {
		s.failPendingJob(ctx, jobID, err.Error())
		return err
	}
	_, err = s.client.Enqueue(task, asynq.TaskID(scanTaskID(repoID)))
	if err != nil {
		if errors.Is(err, asynq.ErrDuplicateTask) || errors.Is(err, asynq.ErrTaskIDConflict) {
			s.failPendingJob(ctx, jobID, "duplicate task suppressed")
			return repositoriesvc.ErrScanAlreadyQueuedOrRunning
		}
		s.failPendingJob(ctx, jobID, "enqueue failed: "+err.Error())
		return err
	}
	return nil
}

func (s *OrgScheduler) failPendingJob(ctx context.Context, jobID uuid.UUID, errMsg string) {
	now := time.Now()
	_, _ = s.db.Exec(ctx, `
		UPDATE scan_jobs
		SET status = 'failed', completed_at = $1, error_msg = $2
		WHERE id = $3 AND status = 'pending'`,
		now, errMsg, jobID,
	)
}
