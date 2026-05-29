package findings

import (
	"fmt"

	"github.com/purplehatlabs/Baldr/internal/llm"
	"github.com/purplehatlabs/Baldr/internal/models"
)

const lowCVSThreshold = 4.0

type RuleOutcome struct {
	SkipAnalysis        bool
	ForceHumanReview    bool
	AdjustConfidenceCap *float64
	Reason              string
}

func ApplyPreRules(
	status models.FindingStatus,
	severity models.Severity,
	cvssScore *float64,
	minSeverity *models.Severity,
) RuleOutcome {
	if status == models.FindingSuppressed || status == models.FindingFixed {
		return RuleOutcome{
			SkipAnalysis: true,
			Reason:       "finding is suppressed or fixed",
		}
	}

	if minSeverity != nil && !llm.MeetsMinSeverity(severity, *minSeverity) {
		return RuleOutcome{
			SkipAnalysis: true,
			Reason: fmt.Sprintf(
				"severity %s below tenant auto-analysis threshold (%s)",
				severity,
				*minSeverity,
			),
		}
	}

	if cvssScore != nil && *cvssScore < lowCVSThreshold && severity != models.SeverityCritical {
		cap := 0.6
		return RuleOutcome{
			ForceHumanReview:    true,
			AdjustConfidenceCap: &cap,
			Reason:              "low CVSS score with non-critical severity",
		}
	}

	return RuleOutcome{}
}

type FinalVerdict struct {
	CriticalityVerdict    models.CriticalityVerdict
	ExploitabilityVerdict models.ExploitabilityVerdict
	Confidence            float64
	Reasoning             string
}

func MergeWithLLM(
	pre RuleOutcome,
	llmResult *llm.AnalysisResult,
	severity models.Severity,
) FinalVerdict {
	criticality := mapCriticalityVerdict(llmResult.CriticalityVerdict)
	exploitability := mapExploitabilityVerdict(llmResult.Exploitability)
	confidence := llmResult.Confidence
	reasoning := llmResult.Reasoning

	if pre.ForceHumanReview {
		criticality = models.VerdictNeedsHumanReview
		if reasoning != "" {
			reasoning = pre.Reason + "; " + reasoning
		} else {
			reasoning = pre.Reason
		}
	}

	if pre.AdjustConfidenceCap != nil && confidence > *pre.AdjustConfidenceCap {
		confidence = *pre.AdjustConfidenceCap
	}

	if llmResult.IsCritical && severity == models.SeverityLow && criticality == models.VerdictTrueCritical {
		criticality = models.VerdictNeedsHumanReview
		reasoning = "LLM marked critical but scanner severity is low; " + reasoning
	}

	if llmResult.IsExploitable && exploitability == models.ExploitNone {
		exploitability = models.ExploitLow
	}

	if !llmResult.IsExploitable && exploitability != models.ExploitNone && exploitability != models.ExploitLow {
		criticality = models.VerdictNeedsHumanReview
		reasoning = "LLM exploitability inconsistent with is_exploitable flag; " + reasoning
	}

	return FinalVerdict{
		CriticalityVerdict:    criticality,
		ExploitabilityVerdict: exploitability,
		Confidence:            confidence,
		Reasoning:             reasoning,
	}
}

func mapCriticalityVerdict(v string) models.CriticalityVerdict {
	switch v {
	case string(models.VerdictTrueCritical):
		return models.VerdictTrueCritical
	case string(models.VerdictFalsePositive):
		return models.VerdictFalsePositive
	case string(models.VerdictInformational):
		return models.VerdictInformational
	case string(models.VerdictNeedsHumanReview):
		return models.VerdictNeedsHumanReview
	default:
		return models.VerdictNeedsHumanReview
	}
}

func mapExploitabilityVerdict(v string) models.ExploitabilityVerdict {
	switch v {
	case string(models.ExploitNone):
		return models.ExploitNone
	case string(models.ExploitLow):
		return models.ExploitLow
	case string(models.ExploitMedium):
		return models.ExploitMedium
	case string(models.ExploitHigh):
		return models.ExploitHigh
	case string(models.ExploitCritical):
		return models.ExploitCritical
	default:
		return models.ExploitLow
	}
}
