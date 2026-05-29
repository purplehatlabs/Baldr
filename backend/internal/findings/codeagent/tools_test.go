package codeagent

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestToolExecutor_searchCodeAndReadFile(t *testing.T) {
	root := t.TempDir()
	srcDir := filepath.Join(root, "src")
	if err := os.MkdirAll(srcDir, 0750); err != nil {
		t.Fatal(err)
	}
	filePath := filepath.Join(srcDir, "main.go")
	if err := os.WriteFile(filePath, []byte("package main\nimport \"github.com/vuln/pkg\"\nfunc main(){ pkg.Run() }\n"), 0644); err != nil {
		t.Fatal(err)
	}

	exec := NewToolExecutor(root, []string{"src/main.go"}, 0)
	searchOut, err := exec.Execute("search_code", json.RawMessage(`{"query":"github.com/vuln/pkg"}`))
	if err != nil {
		t.Fatalf("search_code failed: %v", err)
	}
	if !strings.Contains(searchOut, "src/main.go") {
		t.Fatalf("expected match in search output, got %q", searchOut)
	}

	readOut, err := exec.Execute("read_file", json.RawMessage(`{"path":"src/main.go","start_line":1,"end_line":3}`))
	if err != nil {
		t.Fatalf("read_file failed: %v", err)
	}
	if !strings.Contains(readOut, "package main") {
		t.Fatalf("expected file contents, got %q", readOut)
	}
}

func TestToolExecutor_readFileRejectsEscape(t *testing.T) {
	root := t.TempDir()
	exec := NewToolExecutor(root, nil, 0)
	_, err := exec.Execute("read_file", json.RawMessage(`{"path":"../secret.txt"}`))
	if err == nil {
		t.Fatal("expected path escape to fail")
	}
}

func TestToolExecutor_listImportSites(t *testing.T) {
	exec := NewToolExecutor("/tmp", []string{"src/a.go", "src/b.go"}, 3)
	out, err := exec.Execute("list_import_sites", json.RawMessage(`{"package_name":"pkg"}`))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "src/a.go") {
		t.Fatalf("expected import sites, got %q", out)
	}
	if !strings.Contains(out, "+3 more import sites omitted") {
		t.Fatalf("expected omitted notice, got %q", out)
	}
}
