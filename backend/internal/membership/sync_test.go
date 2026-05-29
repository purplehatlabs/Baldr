package membership

import (
	"testing"

	"github.com/google/uuid"
)

func TestGithubIDsEmptyUsesSentinel(t *testing.T) {
	ids := githubIDs(map[int64]uuid.UUID{})
	if len(ids) != 1 || ids[0] != -1 {
		t.Fatalf("expected sentinel for empty set, got %v", ids)
	}
}

func TestGithubIDsCollectsKeys(t *testing.T) {
	seen := map[int64]uuid.UUID{10: {}, 20: {}}
	ids := githubIDs(seen)
	if len(ids) != 2 {
		t.Fatalf("expected 2 ids, got %d", len(ids))
	}
}
