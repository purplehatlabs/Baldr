package middleware

import (
	"testing"

	"github.com/purplehatlabs/Baldr/internal/models"
)

func TestHasRole(t *testing.T) {
	if !HasRole("admin", models.RoleAdmin, models.RoleOwner) {
		t.Fatal("admin should match admin or owner")
	}
	if HasRole("member", models.RoleAdmin, models.RoleOwner) {
		t.Fatal("member should not match admin or owner")
	}
}
