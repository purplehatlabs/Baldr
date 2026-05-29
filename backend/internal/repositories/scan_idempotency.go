package repositories

import (
	"context"
	"errors"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// ErrScanAlreadyQueuedOrRunning is returned when a repo already has a pending or
// running scan job. API handlers map this to HTTP 409 with code
// scan_already_queued_or_running.
var ErrScanAlreadyQueuedOrRunning = errors.New("scan_already_queued_or_running")

const activeScanJobIndex = "idx_scan_jobs_one_active_per_repo"

// HasActiveScanJob reports whether the repo has a scan job in pending or running state.
func HasActiveScanJob(ctx context.Context, db *pgxpool.Pool, repoID uuid.UUID) (bool, error) {
	var exists bool
	err := db.QueryRow(ctx, `
		SELECT EXISTS(
			SELECT 1 FROM scan_jobs
			WHERE repo_id = $1 AND status IN ('pending', 'running')
		)`, repoID,
	).Scan(&exists)
	return exists, err
}

// IsActiveScanUniqueViolation detects the partial unique index violation that
// guards against concurrent enqueue races for the same repo.
func IsActiveScanUniqueViolation(err error) bool {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		return pgErr.Code == "23505" && pgErr.ConstraintName == activeScanJobIndex
	}
	return false
}
