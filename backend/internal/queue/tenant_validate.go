package queue

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

func validateFindingTenant(ctx context.Context, db *pgxpool.Pool, findingID, tenantID uuid.UUID) error {
	var dbTenantID uuid.UUID
	err := db.QueryRow(ctx, `SELECT tenant_id FROM findings WHERE id = $1`, findingID).Scan(&dbTenantID)
	if err != nil {
		if err == pgx.ErrNoRows {
			return fmt.Errorf("finding not found: %s", findingID)
		}
		return fmt.Errorf("load finding tenant: %w", err)
	}
	if dbTenantID != tenantID {
		return fmt.Errorf("tenant_id mismatch for finding %s", findingID)
	}
	return nil
}
