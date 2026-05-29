package codeagent

import (
	"regexp"
	"strings"
)

const maxAdvisorySearchHints = 8

var (
	backtickPattern        = regexp.MustCompile("`([^`]+)`")
	underscoreIdentPattern = regexp.MustCompile(`\b_[A-Za-z][A-Za-z0-9_]{1,48}\b`)
	camelAPIPattern        = regexp.MustCompile(`\b[A-Z][A-Za-z0-9]{2,}(?:[A-Z][a-z0-9]+)+\b`)
)

// ExtractAdvisorySearchHints pulls concrete search terms from OSV/advisory text so
// the agent can target vulnerable APIs instead of broad package-name searches.
func ExtractAdvisorySearchHints(summary, details string) []string {
	text := summary + "\n" + details
	seen := make(map[string]struct{})
	hints := make([]string, 0, maxAdvisorySearchHints)

	add := func(raw string) {
		raw = strings.TrimSpace(raw)
		if raw == "" || len(raw) > 64 {
			return
		}
		key := strings.ToLower(raw)
		if _, ok := seen[key]; ok {
			return
		}
		if isNoiseSearchHint(raw) {
			return
		}
		seen[key] = struct{}{}
		hints = append(hints, raw)
	}

	for _, m := range backtickPattern.FindAllStringSubmatch(text, 12) {
		if len(m) > 1 {
			add(m[1])
		}
	}
	for _, m := range underscoreIdentPattern.FindAllString(text, 12) {
		add(m)
	}
	for _, m := range camelAPIPattern.FindAllString(text, 12) {
		add(m)
	}

	if len(hints) > maxAdvisorySearchHints {
		return hints[:maxAdvisorySearchHints]
	}
	return hints
}

func isNoiseSearchHint(hint string) bool {
	lower := strings.ToLower(hint)
	switch lower {
	case "the", "this", "that", "none", "null", "true", "false", "unknown":
		return true
	}
	if strings.HasPrefix(lower, "http://") || strings.HasPrefix(lower, "https://") {
		return true
	}
	return false
}
