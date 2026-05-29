package codeagent

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

type ToolExecutor struct {
	repoRoot           string
	importSites        []string
	importSitesOmitted int
	maxOutput          int
}

func NewToolExecutor(repoRoot string, importSites []string, importSitesOmitted int) *ToolExecutor {
	return &ToolExecutor{
		repoRoot:           repoRoot,
		importSites:        importSites,
		importSitesOmitted: importSitesOmitted,
		maxOutput:          DefaultMaxOutput,
	}
}

func (e *ToolExecutor) Execute(name string, argsJSON json.RawMessage) (string, error) {
	switch name {
	case "search_code":
		return e.searchCode(argsJSON)
	case "read_file":
		return e.readFile(argsJSON)
	case "list_import_sites":
		return e.listImportSites(argsJSON)
	default:
		return "", fmt.Errorf("unknown tool: %s", name)
	}
}

type searchCodeArgs struct {
	Query    string `json:"query"`
	PathGlob string `json:"path_glob,omitempty"`
}

func (e *ToolExecutor) searchCode(argsJSON json.RawMessage) (string, error) {
	var args searchCodeArgs
	if err := json.Unmarshal(argsJSON, &args); err != nil {
		return "", fmt.Errorf("invalid search_code args: %w", err)
	}
	query := strings.TrimSpace(args.Query)
	if query == "" {
		return "", fmt.Errorf("query is required")
	}

	matches := []string{}
	_ = filepath.WalkDir(e.repoRoot, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() && shouldSkipSearchPath(path) {
			return filepath.SkipDir
		}
		if d.IsDir() || shouldSkipSearchPath(path) {
			return nil
		}
		if args.PathGlob != "" && !matchSimpleGlob(filepath.Base(path), args.PathGlob) {
			return nil
		}
		content, err := os.ReadFile(path)
		if err != nil {
			return nil
		}
		lines := strings.Split(string(content), "\n")
		for i, line := range lines {
			if strings.Contains(line, query) {
				rel, _ := filepath.Rel(e.repoRoot, path)
				matches = append(matches, fmt.Sprintf("%s:%d:%s", rel, i+1, strings.TrimSpace(line)))
				if len(strings.Join(matches, "\n")) > e.maxOutput {
					return filepath.SkipAll
				}
			}
		}
		return nil
	})

	if len(matches) == 0 {
		return "No matches found.", nil
	}
	out := strings.Join(matches, "\n")
	return truncateOutput(out, e.maxOutput), nil
}

type readFileArgs struct {
	Path      string `json:"path"`
	StartLine *int   `json:"start_line,omitempty"`
	EndLine   *int   `json:"end_line,omitempty"`
}

func (e *ToolExecutor) readFile(argsJSON json.RawMessage) (string, error) {
	var args readFileArgs
	if err := json.Unmarshal(argsJSON, &args); err != nil {
		return "", fmt.Errorf("invalid read_file args: %w", err)
	}
	abs, err := e.safePath(args.Path)
	if err != nil {
		return "", err
	}
	file, err := os.Open(abs)
	if err != nil {
		return "", fmt.Errorf("open file: %w", err)
	}
	defer file.Close()

	start := 1
	end := 1<<31 - 1
	if args.StartLine != nil && *args.StartLine > 0 {
		start = *args.StartLine
	}
	if args.EndLine != nil && *args.EndLine >= start {
		end = *args.EndLine
	}

	var b strings.Builder
	scanner := bufio.NewScanner(file)
	lineNum := 0
	for scanner.Scan() {
		lineNum++
		if lineNum < start {
			continue
		}
		if lineNum > end {
			break
		}
		fmt.Fprintf(&b, "%d|%s\n", lineNum, scanner.Text())
	}
	if b.Len() == 0 {
		return "File empty or line range out of bounds.", nil
	}
	return truncateOutput(b.String(), e.maxOutput), scanner.Err()
}

type listImportSitesArgs struct {
	PackageName string `json:"package_name"`
}

func (e *ToolExecutor) listImportSites(argsJSON json.RawMessage) (string, error) {
	var args listImportSitesArgs
	if err := json.Unmarshal(argsJSON, &args); err != nil {
		return "", fmt.Errorf("invalid list_import_sites args: %w", err)
	}
	if len(e.importSites) == 0 {
		return "No application import sites known from reachability analysis (manifest/lockfile-only matches are excluded).", nil
	}
	out := strings.Join(e.importSites, "\n")
	if e.importSitesOmitted > 0 {
		out += fmt.Sprintf(
			"\n...(+%d more import sites omitted; use search_code with path_glob such as *.py to narrow)",
			e.importSitesOmitted,
		)
	}
	return out, nil
}

func (e *ToolExecutor) safePath(rel string) (string, error) {
	clean := filepath.Clean(rel)
	if clean == ".." || strings.HasPrefix(clean, ".."+string(os.PathSeparator)) {
		return "", fmt.Errorf("path escapes repository root")
	}
	abs := filepath.Join(e.repoRoot, clean)
	abs, err := filepath.Abs(abs)
	if err != nil {
		return "", err
	}
	root, err := filepath.Abs(e.repoRoot)
	if err != nil {
		return "", err
	}
	if abs != root && !strings.HasPrefix(abs, root+string(os.PathSeparator)) {
		return "", fmt.Errorf("path escapes repository root")
	}
	return abs, nil
}

func shouldSkipSearchPath(path string) bool {
	parts := strings.Split(path, string(os.PathSeparator))
	for _, p := range parts {
		switch p {
		case ".git", "node_modules", "vendor", "dist", "build", ".venv", "__pycache__":
			return true
		}
	}
	ext := strings.ToLower(filepath.Ext(path))
	switch ext {
	case ".png", ".jpg", ".jpeg", ".gif", ".zip", ".tar", ".gz", ".woff", ".woff2", ".pdf", ".bin":
		return true
	}
	return false
}

func matchSimpleGlob(name, glob string) bool {
	glob = strings.TrimSpace(glob)
	if glob == "" || glob == "*" {
		return true
	}
	if strings.HasPrefix(glob, "*.") {
		return strings.HasSuffix(name, glob[1:])
	}
	return name == glob
}

func truncateOutput(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + "\n...(truncated)"
}
