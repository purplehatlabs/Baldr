package queue

import (
	"testing"

	"github.com/purplehatlabs/Baldr/internal/models"
)

func TestMatchesKnownMaliciousIndicatorCaseInsensitive(t *testing.T) {
	t.Parallel()

	matched := matchesKnownMaliciousIndicator(
		"NPM",
		"Left-Pad",
		"1.0.0",
		"npm",
		"left-pad",
		"1.0.0",
	)
	if !matched {
		t.Fatal("expected case-insensitive ecosystem/package match")
	}
}

func TestMatchesKnownMaliciousIndicatorVersionSemantics(t *testing.T) {
	t.Parallel()

	if !matchesKnownMaliciousIndicator("npm", "left-pad", "1.0.0", "npm", "left-pad", "1.0.0") {
		t.Fatal("expected exact version match")
	}
	if !matchesKnownMaliciousIndicator("npm", "left-pad", "1.0.0", "npm", "left-pad", "") {
		t.Fatal("expected wildcard(empty version) match")
	}
	if matchesKnownMaliciousIndicator("npm", "left-pad", "1.0.0", "npm", "left-pad", "9.9.9") {
		t.Fatal("expected mismatched explicit version not to match")
	}

	if got := knownMaliciousVersionPriority("1.0.0", "1.0.0"); got != 0 {
		t.Fatalf("exact version should have highest priority, got %d", got)
	}
	if got := knownMaliciousVersionPriority("1.0.0", ""); got != 1 {
		t.Fatalf("wildcard version should have lower priority, got %d", got)
	}
}

func TestMatchesKnownMaliciousIndicatorNoCrossEcosystemMatch(t *testing.T) {
	t.Parallel()

	matched := matchesKnownMaliciousIndicator(
		"npm",
		"requests",
		"2.31.0",
		"PyPI",
		"requests",
		"2.31.0",
	)
	if matched {
		t.Fatal("expected different ecosystems not to cross-match")
	}
}

func TestPreserveSignalStatusOnConflict(t *testing.T) {
	t.Parallel()

	if got := preserveSignalStatusOnConflict(models.SignalStatusResolved, models.SignalStatusOpen); got != models.SignalStatusResolved {
		t.Fatalf("expected resolved to be preserved, got %s", got)
	}
	if got := preserveSignalStatusOnConflict(models.SignalStatusSuppressed, models.SignalStatusOpen); got != models.SignalStatusSuppressed {
		t.Fatalf("expected suppressed to be preserved, got %s", got)
	}
	if got := preserveSignalStatusOnConflict(models.SignalStatusTriaged, models.SignalStatusOpen); got != models.SignalStatusTriaged {
		t.Fatalf("expected triaged to be preserved, got %s", got)
	}
	if got := preserveSignalStatusOnConflict(models.SignalStatusOpen, models.SignalStatusResolved); got != models.SignalStatusResolved {
		t.Fatalf("expected non-terminal status to update, got %s", got)
	}
}
