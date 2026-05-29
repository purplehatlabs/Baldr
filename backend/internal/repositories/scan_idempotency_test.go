package repositories

import (
	"errors"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
)

func TestIsActiveScanUniqueViolation(t *testing.T) {
	t.Parallel()

	pgErr := &pgconn.PgError{Code: "23505", ConstraintName: activeScanJobIndex}
	if !IsActiveScanUniqueViolation(pgErr) {
		t.Fatal("expected active scan unique violation")
	}

	other := &pgconn.PgError{Code: "23505", ConstraintName: "other_constraint"}
	if IsActiveScanUniqueViolation(other) {
		t.Fatal("expected false for other constraint")
	}

	if IsActiveScanUniqueViolation(errors.New("plain error")) {
		t.Fatal("expected false for non-pg error")
	}
}
