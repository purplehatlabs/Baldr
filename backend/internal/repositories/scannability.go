package repositories

import (
	"context"
	"errors"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

var ErrScanBlockedMissingInternetExposure = errors.New("scan_blocked_missing_internet_exposure")

func EnsureRepoScannable(ctx context.Context, db *pgxpool.Pool, repoID uuid.UUID) error {
	var hasExposure bool
	err := db.QueryRow(ctx, `
		SELECT r.is_internet_exposed IS NOT NULL
		FROM repositories r
		WHERE r.id = $1`,
		repoID,
	).Scan(&hasExposure)
	if err != nil {
		return err
	}
	if !hasExposure {
		return ErrScanBlockedMissingInternetExposure
	}
	return nil
}

func EnsureRepoScannableForTenant(ctx context.Context, db *pgxpool.Pool, repoID, tenantID uuid.UUID) error {
	var hasExposure bool
	err := db.QueryRow(ctx, `
		SELECT r.is_internet_exposed IS NOT NULL
		FROM repositories r
		JOIN organizations o ON o.id = r.org_id
		WHERE r.id = $1 AND o.tenant_id = $2`,
		repoID, tenantID,
	).Scan(&hasExposure)
	if err != nil {
		return err
	}
	if !hasExposure {
		return ErrScanBlockedMissingInternetExposure
	}
	return nil
}

func IsRepoMissingForTenant(err error) bool {
	return errors.Is(err, pgx.ErrNoRows)
}
