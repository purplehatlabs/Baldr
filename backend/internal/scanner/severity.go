package scanner

import (
	"strconv"
	"strings"

	osvmodels "github.com/google/osv-scanner/v2/pkg/models"
	gocvss20 "github.com/pandatix/go-cvss/20"
	gocvss30 "github.com/pandatix/go-cvss/30"
	gocvss31 "github.com/pandatix/go-cvss/31"
	gocvss40 "github.com/pandatix/go-cvss/40"
	internalmodels "github.com/purplehatlabs/Baldr/internal/models"
)

// classifySeverity returns the best severity/score pair for an OSV vulnerability.
//
// OSV vulnerabilities expose severity in several incompatible shapes depending
// on the source database:
//
//   - GHSA (PyPI/npm/Maven) usually only provides CVSS VECTORS (e.g.
//     "CVSS:3.1/AV:N/AC:L/...") in vuln.Severity[].Score, not a numeric base
//     score. They also expose a textual severity at
//     vuln.DatabaseSpecific["severity"] ∈ {LOW, MODERATE, HIGH, CRITICAL}.
//   - Some sources publish the numeric base score directly in Score
//     (e.g. "7.5").
//   - Older entries may carry a CVSS v2 vector ("AV:N/AC:L/Au:N/C:P/I:P/A:P").
//
// We try, in order: numeric score → CVSS vector parsing → GHSA textual fallback.
// When multiple sources are available we keep the highest severity to err on
// the side of caution.
func classifySeverity(vuln osvmodels.Vulnerability) (internalmodels.Severity, *float64) {
	bestSeverity := internalmodels.SeverityUnknown
	var bestScore *float64

	for _, sev := range vuln.Severity {
		score, ok := extractScore(sev)
		if !ok {
			continue
		}
		sevLevel := scoreToSeverity(score)
		if severityRank(sevLevel) > severityRank(bestSeverity) {
			bestSeverity = sevLevel
		}
		if bestScore == nil || score > *bestScore {
			s := score
			bestScore = &s
		}
	}

	if bestSeverity == internalmodels.SeverityUnknown {
		if textual := severityFromDatabaseSpecific(vuln.DatabaseSpecific); textual != internalmodels.SeverityUnknown {
			bestSeverity = textual
		}
	}

	return bestSeverity, bestScore
}

// extractScore returns the CVSS base score for a single Severity entry,
// regardless of whether Score holds a numeric value or a CVSS vector.
func extractScore(sev osvmodels.Severity) (float64, bool) {
	if sev.Score == "" {
		return 0, false
	}

	if f, err := strconv.ParseFloat(strings.TrimSpace(sev.Score), 64); err == nil && f > 0 {
		return f, true
	}

	switch sev.Type {
	case osvmodels.SeverityCVSSV4:
		if v, err := gocvss40.ParseVector(sev.Score); err == nil {
			return v.Score(), true
		}
	case osvmodels.SeverityCVSSV3:
		if strings.HasPrefix(sev.Score, "CVSS:3.1") {
			if v, err := gocvss31.ParseVector(sev.Score); err == nil {
				return v.BaseScore(), true
			}
		}
		if v, err := gocvss30.ParseVector(sev.Score); err == nil {
			return v.BaseScore(), true
		}
		if v, err := gocvss31.ParseVector(sev.Score); err == nil {
			return v.BaseScore(), true
		}
	case osvmodels.SeverityCVSSV2:
		if v, err := gocvss20.ParseVector(sev.Score); err == nil {
			return v.BaseScore(), true
		}
	}

	return 0, false
}

func scoreToSeverity(score float64) internalmodels.Severity {
	switch {
	case score >= 9.0:
		return internalmodels.SeverityCritical
	case score >= 7.0:
		return internalmodels.SeverityHigh
	case score >= 4.0:
		return internalmodels.SeverityMedium
	case score > 0:
		return internalmodels.SeverityLow
	default:
		return internalmodels.SeverityUnknown
	}
}

// severityFromDatabaseSpecific reads the GHSA-style textual severity stored in
// the database_specific blob (used when no CVSS score is available).
func severityFromDatabaseSpecific(ds map[string]interface{}) internalmodels.Severity {
	if ds == nil {
		return internalmodels.SeverityUnknown
	}
	raw, ok := ds["severity"].(string)
	if !ok {
		return internalmodels.SeverityUnknown
	}
	switch strings.ToUpper(strings.TrimSpace(raw)) {
	case "CRITICAL":
		return internalmodels.SeverityCritical
	case "HIGH":
		return internalmodels.SeverityHigh
	case "MODERATE", "MEDIUM":
		return internalmodels.SeverityMedium
	case "LOW":
		return internalmodels.SeverityLow
	default:
		return internalmodels.SeverityUnknown
	}
}

func severityRank(s internalmodels.Severity) int {
	switch s {
	case internalmodels.SeverityCritical:
		return 4
	case internalmodels.SeverityHigh:
		return 3
	case internalmodels.SeverityMedium:
		return 2
	case internalmodels.SeverityLow:
		return 1
	default:
		return 0
	}
}
