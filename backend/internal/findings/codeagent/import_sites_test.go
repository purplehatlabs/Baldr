package codeagent

import (
	"strings"
	"testing"
)

func TestPrepareImportSitesForAgent_excludesLockfilesAndCaps(t *testing.T) {
	raw := make([]string, 0, 30)
	raw = append(raw, "poetry.lock", "pyproject.toml", "requirements.txt")
	for i := 0; i < 30; i++ {
		raw = append(raw, "app/module_"+string(rune('a'+i%26))+".py")
	}

	prepared, total, omitted := PrepareImportSitesForAgent(raw)
	if total != 33 {
		t.Fatalf("expected total 33, got %d", total)
	}
	if omitted != 5 {
		t.Fatalf("expected 5 omitted (30 app files capped to 25), got %d", omitted)
	}
	if len(prepared) != MaxImportSites {
		t.Fatalf("expected %d prepared sites, got %d", MaxImportSites, len(prepared))
	}
	for _, site := range prepared {
		if isLockOrManifestPath(site) {
			t.Fatalf("lock/manifest path should be excluded: %s", site)
		}
	}
}

func TestPrepareImportSitesForAgent_deprioritizesTests(t *testing.T) {
	raw := []string{
		"tests/test_views.py",
		"app/views.py",
		"api/migrations/0001_initial.py",
		"app/services/order.py",
	}

	prepared, _, _ := PrepareImportSitesForAgent(raw)
	if len(prepared) != 4 {
		t.Fatalf("expected 4 prepared, got %d", len(prepared))
	}
	if prepared[0] != "app/views.py" || prepared[1] != "app/services/order.py" {
		t.Fatalf("expected app paths first, got %v", prepared)
	}
	if !strings.Contains(prepared[2], "tests/") || !strings.Contains(prepared[3], "migrations/") {
		t.Fatalf("expected deprioritized paths last, got %v", prepared)
	}
}

func TestPrepareImportSitesForAgent_emptyAfterFiltering(t *testing.T) {
	prepared, total, omitted := PrepareImportSitesForAgent([]string{"poetry.lock", "Pipfile.lock"})
	if total != 2 {
		t.Fatalf("expected total 2, got %d", total)
	}
	if len(prepared) != 0 || omitted != 0 {
		t.Fatalf("expected empty prepared, got %v omitted=%d", prepared, omitted)
	}
}
