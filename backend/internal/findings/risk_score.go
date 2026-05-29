package findings

import (
	"encoding/json"
	"fmt"
	"math"
	"strings"
	"time"

	"github.com/purplehatlabs/Baldr/internal/models"
)

type RiskScoreInput struct {
	Severity                models.Severity
	CVSSScore               *float64
	Status                  models.FindingStatus
	FixedVersion            *string
	FirstSeenAt             time.Time
	ReachabilityStatus      models.ReachabilityStatus
	ReachabilityConfidence  *float64
	Exploitability          *models.ExploitabilityVerdict
	CriticalityVerdict      *models.CriticalityVerdict
	LLMConfidence           *float64
	VulnerablePathConfirmed bool
	HasActiveException      bool
	SLAHours                *int
	EPSSScore               *float64
	EPSSPercentile          *float64
	KEVListed               bool
	AssetCriticality        string
	DataSensitivity         string
	Environment             string
	IsInternetExposed       *bool
	HasContextualAnalysis   bool
}

type RiskFactor struct {
	Name   string  `json:"name"`
	Points float64 `json:"points"`
	Detail string  `json:"detail,omitempty"`
}

type RiskScoreResult struct {
	Score       float64
	Tier        models.RiskTier
	Factors     []RiskFactor
	SLADueAt    *time.Time
	IsSLABreach bool
}

func CalculateRiskScore(in RiskScoreInput, now time.Time) RiskScoreResult {
	if in.Status == models.FindingSuppressed || in.Status == models.FindingFixed {
		return RiskScoreResult{
			Score:   0,
			Tier:    models.RiskTierLow,
			Factors: []RiskFactor{{Name: "status", Points: 0, Detail: string(in.Status)}},
		}
	}
	if in.HasActiveException {
		return RiskScoreResult{
			Score:   0,
			Tier:    models.RiskTierLow,
			Factors: []RiskFactor{{Name: "exception", Points: 0, Detail: "active exception"}},
		}
	}

	factors := make([]RiskFactor, 0, 18)

	technicalScore, technicalFactors := calculateTechnicalScore(in, now)
	threatScore, threatFactors := calculateThreatScore(in)
	businessScore, businessFactors := calculateBusinessScore(in)
	factors = append(factors, technicalFactors...)
	factors = append(factors, threatFactors...)
	factors = append(factors, businessFactors...)

	score := 0.45*technicalScore + 0.35*threatScore + 0.20*businessScore
	score = math.Max(0, math.Min(score, 100))

	factors = append(factors,
		RiskFactor{Name: "pillar_technical", Points: 0.45 * technicalScore, Detail: "weight=0.45"},
		RiskFactor{Name: "pillar_threat", Points: 0.35 * threatScore, Detail: "weight=0.35"},
		RiskFactor{Name: "pillar_business", Points: 0.20 * businessScore, Detail: "weight=0.20"},
	)

	tier := tierFromScore(score)
	tier, factors = applyTierOverrides(in, tier, threatScore, factors)
	slaDueAt, slaBreached := evaluateSLA(in, now)

	return RiskScoreResult{
		Score:       round2(score),
		Tier:        tier,
		Factors:     factors,
		SLADueAt:    slaDueAt,
		IsSLABreach: slaBreached,
	}
}

func calculateTechnicalScore(in RiskScoreInput, now time.Time) (float64, []RiskFactor) {
	factors := make([]RiskFactor, 0, 8)
	score := 0.0

	severityPoints := map[models.Severity]float64{
		models.SeverityCritical: 35,
		models.SeverityHigh:     28,
		models.SeverityMedium:   18,
		models.SeverityLow:      8,
		models.SeverityUnknown:  10,
	}
	severityScore := severityPoints[in.Severity]
	severityScore = modulateSeverityByVerdict(severityScore, in.CriticalityVerdict)
	score += severityScore
	factors = append(factors, RiskFactor{Name: "technical.severity", Points: severityScore, Detail: string(in.Severity)})

	if in.CVSSScore != nil {
		cvssPoints := math.Min(*in.CVSSScore*2.5, 25)
		score += cvssPoints
		factors = append(factors, RiskFactor{Name: "technical.cvss", Points: cvssPoints, Detail: formatFloat(*in.CVSSScore)})
	}

	switch in.ReachabilityStatus {
	case models.ReachabilityReachable:
		reachPoints := 20.0
		if in.ReachabilityConfidence != nil {
			reachPoints = 20.0 * (*in.ReachabilityConfidence)
		}
		score += reachPoints
		factors = append(factors, RiskFactor{Name: "technical.reachability", Points: reachPoints, Detail: "reachable"})
	case models.ReachabilityUnreachable:
		score -= 8
		factors = append(factors, RiskFactor{Name: "technical.reachability", Points: -8, Detail: "unreachable"})
	default:
		score += 6
		factors = append(factors, RiskFactor{Name: "technical.reachability", Points: 6, Detail: "unknown"})
	}

	if in.VulnerablePathConfirmed {
		score += 10
		factors = append(factors, RiskFactor{Name: "technical.vulnerable_path_confirmed", Points: 10, Detail: "agent_confirmed"})
	}

	if in.Exploitability != nil {
		exploitPoints := map[models.ExploitabilityVerdict]float64{
			models.ExploitNone:     -3,
			models.ExploitLow:      5,
			models.ExploitMedium:   12,
			models.ExploitHigh:     18,
			models.ExploitCritical: 22,
		}
		points := exploitPoints[*in.Exploitability]
		if in.LLMConfidence != nil && in.HasContextualAnalysis {
			points *= *in.LLMConfidence
		}
		score += points
		factors = append(factors, RiskFactor{Name: "technical.exploitability", Points: points, Detail: string(*in.Exploitability)})
	}

	ageHours := now.Sub(in.FirstSeenAt).Hours()
	if ageHours > 0 {
		agePoints := math.Min(ageHours/24*0.2, 6)
		if agePoints > 0 {
			score += agePoints
			factors = append(factors, RiskFactor{Name: "technical.age", Points: agePoints, Detail: formatFloat(ageHours) + "h"})
		}
	}

	if in.FixedVersion != nil && *in.FixedVersion != "" {
		score -= 5
		factors = append(factors, RiskFactor{Name: "technical.fix_available", Points: -5, Detail: *in.FixedVersion})
	}

	return clamp100(score), factors
}

func calculateThreatScore(in RiskScoreInput) (float64, []RiskFactor) {
	factors := make([]RiskFactor, 0, 4)
	score := 0.0

	if in.EPSSPercentile != nil {
		percentilePoints := clamp100(*in.EPSSPercentile * 100)
		score += percentilePoints
		factors = append(factors, RiskFactor{
			Name:   "threat.epss_percentile",
			Points: percentilePoints,
			Detail: formatFloat(*in.EPSSPercentile),
		})
	} else if in.EPSSScore != nil {
		epssPoints := clamp100(*in.EPSSScore * 100)
		score += epssPoints
		factors = append(factors, RiskFactor{
			Name:   "threat.epss_score",
			Points: epssPoints,
			Detail: formatFloat(*in.EPSSScore),
		})
	} else {
		factors = append(factors, RiskFactor{Name: "threat.epss_score", Points: 0, Detail: "unavailable"})
	}

	if in.KEVListed {
		score += 35
		factors = append(factors, RiskFactor{Name: "threat.kev", Points: 35, Detail: "listed"})
	} else {
		factors = append(factors, RiskFactor{Name: "threat.kev", Points: 0, Detail: "not_listed"})
	}

	return clamp100(score), factors
}

func calculateBusinessScore(in RiskScoreInput) (float64, []RiskFactor) {
	factors := make([]RiskFactor, 0, 5)
	score := 0.0

	criticalityPoints := map[string]float64{
		"low":      8,
		"medium":   18,
		"high":     28,
		"critical": 36,
	}
	criticality := normalizedOrDefault(in.AssetCriticality, "medium")
	score += criticalityPoints[criticality]
	factors = append(factors, RiskFactor{Name: "business.asset_criticality", Points: criticalityPoints[criticality], Detail: criticality})

	sensitivityPoints := map[string]float64{
		"public":       2,
		"internal":     10,
		"confidential": 22,
		"restricted":   30,
	}
	sensitivity := normalizedOrDefault(in.DataSensitivity, "internal")
	score += sensitivityPoints[sensitivity]
	factors = append(factors, RiskFactor{Name: "business.data_sensitivity", Points: sensitivityPoints[sensitivity], Detail: sensitivity})

	environmentPoints := map[string]float64{
		"dev":     4,
		"staging": 10,
		"prod":    20,
	}
	environment := normalizedOrDefault(in.Environment, "prod")
	score += environmentPoints[environment]
	factors = append(factors, RiskFactor{Name: "business.environment", Points: environmentPoints[environment], Detail: environment})

	switch {
	case in.IsInternetExposed == nil:
		score += 7
		factors = append(factors, RiskFactor{Name: "business.internet_exposure", Points: 7, Detail: "unknown"})
	case *in.IsInternetExposed:
		score += 15
		factors = append(factors, RiskFactor{Name: "business.internet_exposure", Points: 15, Detail: "internet_exposed"})
	default:
		factors = append(factors, RiskFactor{Name: "business.internet_exposure", Points: 0, Detail: "internal_only"})
	}

	return clamp100(score), factors
}

func applyTierOverrides(in RiskScoreInput, tier models.RiskTier, threatScore float64, factors []RiskFactor) (models.RiskTier, []RiskFactor) {
	updatedTier := tier

	if in.KEVListed && in.ReachabilityStatus == models.ReachabilityReachable && riskTierLessThan(updatedTier, models.RiskTierHigh) {
		updatedTier = models.RiskTierHigh
		factors = append(factors, RiskFactor{
			Name:   "override.kev_reachable_minimum",
			Points: 0,
			Detail: "minimum_high",
		})
	}

	if in.IsInternetExposed != nil && *in.IsInternetExposed &&
		in.Exploitability != nil &&
		exploitabilityAtLeast(*in.Exploitability, models.ExploitMedium) &&
		riskTierLessThan(updatedTier, models.RiskTierHigh) {
		updatedTier = models.RiskTierHigh
		factors = append(factors, RiskFactor{
			Name:   "override.internet_exposed_exploitable_minimum",
			Points: 0,
			Detail: "minimum_high",
		})
	}

	if in.Severity == models.SeverityCritical &&
		in.ReachabilityStatus == models.ReachabilityUnreachable &&
		!in.KEVListed &&
		threatScore < 20 {
		downgraded := downgradeTier(updatedTier)
		if riskTierLessThan(downgraded, models.RiskTierMedium) {
			downgraded = models.RiskTierMedium
		}
		if downgraded != updatedTier {
			updatedTier = downgraded
			factors = append(factors, RiskFactor{
				Name:   "override.unreachable_low_threat",
				Points: 0,
				Detail: "downgraded_one_tier",
			})
		}
	}

	return updatedTier, factors
}

func tierFromScore(score float64) models.RiskTier {
	switch {
	case score >= 75:
		return models.RiskTierCritical
	case score >= 50:
		return models.RiskTierHigh
	case score >= 25:
		return models.RiskTierMedium
	default:
		return models.RiskTierLow
	}
}

func evaluateSLA(in RiskScoreInput, now time.Time) (*time.Time, bool) {
	hours := defaultSLAHours(in.Severity)
	if in.HasContextualAnalysis {
		hours = defaultSLAHoursByTier(tierFromScore(calculateRawScore(in, now)))
	}
	if in.SLAHours != nil && *in.SLAHours > 0 {
		hours = *in.SLAHours
	}
	due := in.FirstSeenAt.Add(time.Duration(hours) * time.Hour)
	breached := in.Status == models.FindingOpen && now.After(due)
	return &due, breached
}

func calculateRawScore(in RiskScoreInput, now time.Time) float64 {
	technicalScore, _ := calculateTechnicalScore(in, now)
	threatScore, _ := calculateThreatScore(in)
	businessScore, _ := calculateBusinessScore(in)
	score := 0.45*technicalScore + 0.35*threatScore + 0.20*businessScore
	return math.Max(0, math.Min(score, 100))
}

func defaultSLAHoursByTier(tier models.RiskTier) int {
	switch tier {
	case models.RiskTierCritical:
		return 7 * 24
	case models.RiskTierHigh:
		return 30 * 24
	case models.RiskTierMedium:
		return 90 * 24
	default:
		return 180 * 24
	}
}

func modulateSeverityByVerdict(base float64, verdict *models.CriticalityVerdict) float64 {
	if verdict == nil {
		return base
	}
	switch *verdict {
	case models.VerdictFalsePositive:
		return math.Min(base, 5)
	case models.VerdictInformational:
		return math.Min(base, 15)
	case models.VerdictTrueCritical:
		return base
	default:
		return base
	}
}

func exploitabilityAtLeast(v, min models.ExploitabilityVerdict) bool {
	rank := map[models.ExploitabilityVerdict]int{
		models.ExploitNone:     0,
		models.ExploitLow:      1,
		models.ExploitMedium:   2,
		models.ExploitHigh:     3,
		models.ExploitCritical: 4,
	}
	return rank[v] >= rank[min]
}

func defaultSLAHours(severity models.Severity) int {
	switch severity {
	case models.SeverityCritical:
		return 7 * 24
	case models.SeverityHigh:
		return 30 * 24
	case models.SeverityMedium:
		return 90 * 24
	default:
		return 180 * 24
	}
}

func MarshalRiskFactors(factors []RiskFactor) ([]byte, error) {
	return json.Marshal(factors)
}

func formatFloat(v float64) string {
	return fmt.Sprintf("%.1f", v)
}

func round2(v float64) float64 {
	return math.Round(v*100) / 100
}

func clamp100(v float64) float64 {
	return math.Max(0, math.Min(v, 100))
}

func normalizedOrDefault(raw, fallback string) string {
	v := strings.TrimSpace(strings.ToLower(raw))
	if v == "" {
		return fallback
	}
	return v
}

func downgradeTier(tier models.RiskTier) models.RiskTier {
	switch tier {
	case models.RiskTierCritical:
		return models.RiskTierHigh
	case models.RiskTierHigh:
		return models.RiskTierMedium
	case models.RiskTierMedium:
		return models.RiskTierLow
	default:
		return models.RiskTierLow
	}
}

func riskTierLessThan(a, b models.RiskTier) bool {
	return riskTierRank(a) < riskTierRank(b)
}

func riskTierRank(tier models.RiskTier) int {
	switch tier {
	case models.RiskTierCritical:
		return 4
	case models.RiskTierHigh:
		return 3
	case models.RiskTierMedium:
		return 2
	default:
		return 1
	}
}
