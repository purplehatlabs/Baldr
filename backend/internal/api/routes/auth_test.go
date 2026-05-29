package routes

import "testing"

func TestRandomStateUnique(t *testing.T) {
	a := randomState()
	b := randomState()
	if a == "" || b == "" || a == b {
		t.Fatal("expected non-empty unique oauth states")
	}
}
