package models

import (
	"time"

	"github.com/google/uuid"
)

type Tenant struct {
	ID        uuid.UUID `json:"id" db:"id"`
	Name      string    `json:"name" db:"name"`
	Slug      string    `json:"slug" db:"slug"`
	CreatedAt time.Time `json:"created_at" db:"created_at"`
}

type UserRole string

const (
	RoleOwner  UserRole = "owner"
	RoleAdmin  UserRole = "admin"
	RoleMember UserRole = "member"
)

type User struct {
	ID           uuid.UUID `json:"id" db:"id"`
	TenantID     uuid.UUID `json:"tenant_id" db:"tenant_id"`
	Email        string    `json:"email" db:"email"`
	GoogleID     *string   `json:"-" db:"google_id"`
	GitHubUserID *int64    `json:"-" db:"github_user_id"`
	GitHubLogin  *string   `json:"github_login,omitempty" db:"github_login"`
	AuthProvider string    `json:"auth_provider,omitempty" db:"auth_provider"`
	Name         string    `json:"name" db:"name"`
	AvatarURL    string    `json:"avatar_url" db:"avatar_url"`
	Role         UserRole  `json:"role" db:"role"`
	Language     string    `json:"language" db:"language"`
	CreatedAt    time.Time `json:"created_at" db:"created_at"`
}

// TenantGitHubAppConfig stores the per-tenant GitHub App credentials.
// The private key is AES-GCM encrypted; never expose it through the API.
type TenantGitHubAppConfig struct {
	TenantID            uuid.UUID  `json:"tenant_id" db:"tenant_id"`
	AppID               int64      `json:"app_id" db:"app_id"`
	PrivateKeyEncrypted []byte     `json:"-" db:"private_key_encrypted"`
	UpdatedByUserID     *uuid.UUID `json:"updated_by_user_id,omitempty" db:"updated_by_user_id"`
	UpdatedAt           time.Time  `json:"updated_at" db:"updated_at"`
	CreatedAt           time.Time  `json:"created_at" db:"created_at"`
}

// TenantLLMConfig holds the per-tenant LiteLLM/OpenAI-compatible endpoint.
// The API key is AES-GCM encrypted; never expose it through the API.
type TenantLLMConfig struct {
	TenantID         uuid.UUID  `json:"tenant_id" db:"tenant_id"`
	BaseURL          string     `json:"base_url" db:"base_url"`
	Model            string     `json:"model" db:"model"`
	DefaultModel     string     `json:"default_model" db:"default_model"`
	AgenticModel     *string    `json:"agentic_model,omitempty" db:"agentic_model"`
	TranslationModel *string    `json:"translation_model,omitempty" db:"translation_model"`
	BatchEnabled     bool       `json:"batch_enabled" db:"batch_enabled"`
	BatchMode        string     `json:"batch_mode" db:"batch_mode"`
	APIKeyEncrypted  []byte     `json:"-" db:"api_key_encrypted"`
	TimeoutSeconds   int        `json:"timeout_seconds" db:"timeout_seconds"`
	UpdatedByUserID  *uuid.UUID `json:"updated_by_user_id,omitempty" db:"updated_by_user_id"`
	UpdatedAt        time.Time  `json:"updated_at" db:"updated_at"`
	CreatedAt        time.Time  `json:"created_at" db:"created_at"`
}

type LLMDispatchMode string

const (
	LLMDispatchRealtime      LLMDispatchMode = "realtime"
	LLMDispatchBatchPending  LLMDispatchMode = "batch_pending"
	LLMDispatchBatchDone     LLMDispatchMode = "batch_done"
	LLMDispatchBatchFallback LLMDispatchMode = "batch_fallback"
)

type Organization struct {
	ID                      uuid.UUID `json:"id" db:"id"`
	TenantID                uuid.UUID `json:"tenant_id" db:"tenant_id"`
	GithubOrgLogin          string    `json:"github_org_login" db:"github_org_login"`
	GithubAppInstallationID *int64    `json:"github_app_installation_id" db:"github_app_installation_id"`
	ScanCron                string    `json:"scan_cron" db:"scan_cron"`
	IsActive                bool      `json:"is_active" db:"is_active"`
	CreatedAt               time.Time `json:"created_at" db:"created_at"`
}

type Repository struct {
	ID                uuid.UUID   `json:"id" db:"id"`
	OrgID             uuid.UUID   `json:"org_id" db:"org_id"`
	GithubRepoID      int64       `json:"github_repo_id" db:"github_repo_id"`
	FullName          string      `json:"full_name" db:"full_name"`
	DefaultBranch     string      `json:"default_branch" db:"default_branch"`
	IsArchived        bool        `json:"is_archived" db:"is_archived"`
	IsMonorepo        bool        `json:"is_monorepo" db:"is_monorepo"`
	IsInternetExposed *bool       `json:"is_internet_exposed" db:"is_internet_exposed"`
	ExposureSource    *string     `json:"exposure_source,omitempty" db:"exposure_source"`
	ExposureUpdatedAt *time.Time  `json:"exposure_updated_at,omitempty" db:"exposure_updated_at"`
	AssetCriticality  string      `json:"asset_criticality" db:"asset_criticality"`
	DataSensitivity   string      `json:"data_sensitivity" db:"data_sensitivity"`
	Environment       string      `json:"environment" db:"environment"`
	LastScannedAt     *time.Time  `json:"last_scanned_at" db:"last_scanned_at"`
	LatestScanStatus  *ScanStatus `json:"latest_scan_status,omitempty" db:"latest_scan_status"`
	CreatedAt         time.Time   `json:"created_at" db:"created_at"`
}

type ScanJobWithRepo struct {
	ScanJob
	RepoFullName string `json:"repo_full_name"`
}

type ScanStatus string

const (
	ScanPending   ScanStatus = "pending"
	ScanRunning   ScanStatus = "running"
	ScanCompleted ScanStatus = "completed"
	ScanFailed    ScanStatus = "failed"
)

type ScanTrigger string

const (
	TriggerScheduled ScanTrigger = "scheduled"
	TriggerManual    ScanTrigger = "manual"
	TriggerWebhook   ScanTrigger = "webhook"
)

type ScanJob struct {
	ID          uuid.UUID   `json:"id" db:"id"`
	RepoID      uuid.UUID   `json:"repo_id" db:"repo_id"`
	Status      ScanStatus  `json:"status" db:"status"`
	TriggeredBy ScanTrigger `json:"triggered_by" db:"triggered_by"`
	CommitSHA   string      `json:"commit_sha" db:"commit_sha"`
	StartedAt   *time.Time  `json:"started_at" db:"started_at"`
	CompletedAt *time.Time  `json:"completed_at" db:"completed_at"`
	ErrorMsg    *string     `json:"error_msg,omitempty" db:"error_msg"`
	CreatedAt   time.Time   `json:"created_at" db:"created_at"`
}

type Manifest struct {
	ID        uuid.UUID `json:"id" db:"id"`
	RepoID    uuid.UUID `json:"repo_id" db:"repo_id"`
	Path      string    `json:"path" db:"path"`
	Ecosystem string    `json:"ecosystem" db:"ecosystem"`
	CreatedAt time.Time `json:"created_at" db:"created_at"`
}

type Team struct {
	ID             uuid.UUID `json:"id" db:"id"`
	OrgID          uuid.UUID `json:"org_id" db:"org_id"`
	GithubTeamSlug string    `json:"github_team_slug" db:"github_team_slug"`
	DisplayName    string    `json:"display_name" db:"display_name"`
	CreatedAt      time.Time `json:"created_at" db:"created_at"`
}

type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
	SeverityUnknown  Severity = "unknown"
)

type FindingStatus string

const (
	FindingOpen       FindingStatus = "open"
	FindingSuppressed FindingStatus = "suppressed"
	FindingFixed      FindingStatus = "fixed"
)

type ReachabilityStatus string

const (
	ReachabilityReachable   ReachabilityStatus = "reachable"
	ReachabilityUnknown     ReachabilityStatus = "unknown"
	ReachabilityUnreachable ReachabilityStatus = "unreachable"
)

type RiskTier string

const (
	RiskTierCritical RiskTier = "critical"
	RiskTierHigh     RiskTier = "high"
	RiskTierMedium   RiskTier = "medium"
	RiskTierLow      RiskTier = "low"
)

type TriageStatus string

const (
	TriageNew         TriageStatus = "new"
	TriageNeedsReview TriageStatus = "needs_review"
	TriageConfirmed   TriageStatus = "confirmed"
	TriageDismissed   TriageStatus = "dismissed"
)

type TriageDecisionSource string

const (
	TriageDecisionAutoAI TriageDecisionSource = "auto_ai"
	TriageDecisionManual TriageDecisionSource = "manual"
	TriageDecisionSystem TriageDecisionSource = "system"
)

type SourceEngine string

const (
	SourceEngineOSV      SourceEngine = "osv"
	SourceEngineDataset  SourceEngine = "dataset"
	SourceEngineGuarddog SourceEngine = "guarddog"
	SourceEngineOpenSSF  SourceEngine = "openssf_pa"
	SourceEngineManual   SourceEngine = "manual"
)

type CreateManualFindingRequest struct {
	Summary           string         `json:"summary" binding:"required"`
	Severity          Severity       `json:"severity" binding:"required,oneof=critical high medium low unknown"`
	ExternalReference string         `json:"external_reference" binding:"required"`
	PackageName       string         `json:"package_name"`
	PackageVersion    string         `json:"package_version"`
	ExternalSource    string         `json:"external_source"`
	Details           string         `json:"details"`
	BusinessImpact    string         `json:"business_impact"`
	Evidence          map[string]any `json:"evidence"`
	CVSSScore         *float64       `json:"cvss_score"`
	SLADueAt          *time.Time     `json:"sla_due_at"`
	ReportedAt        *time.Time     `json:"reported_at"`
}

type Finding struct {
	ID                       uuid.UUID             `json:"id" db:"id"`
	TenantID                 uuid.UUID             `json:"tenant_id" db:"tenant_id"`
	ScanJobID                *uuid.UUID            `json:"scan_job_id,omitempty" db:"scan_job_id"`
	ManifestID               *uuid.UUID            `json:"manifest_id,omitempty" db:"manifest_id"`
	OSVID                    string                `json:"osv_id" db:"osv_id"`
	PackageName              string                `json:"package_name" db:"package_name"`
	PackageVersion           string                `json:"package_version" db:"package_version"`
	FixedVersion             *string               `json:"fixed_version,omitempty" db:"fixed_version"`
	Severity                 Severity              `json:"severity" db:"severity"`
	CVSSScore                *float64              `json:"cvss_score,omitempty" db:"cvss_score"`
	Summary                  string                `json:"summary" db:"summary"`
	Details                  string                `json:"details" db:"details"`
	Status                   FindingStatus         `json:"status" db:"status"`
	FirstSeenAt              time.Time             `json:"first_seen_at" db:"first_seen_at"`
	LastSeenAt               time.Time             `json:"last_seen_at" db:"last_seen_at"`
	ReachabilityStatus       ReachabilityStatus    `json:"reachability_status" db:"reachability_status"`
	ReachabilityConfidence   *float64              `json:"reachability_confidence,omitempty" db:"reachability_confidence"`
	ReachabilityEvidenceJSON []byte                `json:"-" db:"reachability_evidence_json"`
	ReachabilityAnalyzedAt   *time.Time            `json:"reachability_analyzed_at,omitempty" db:"reachability_analyzed_at"`
	RiskScore                float64               `json:"risk_score" db:"risk_score"`
	RiskTier                 RiskTier              `json:"risk_tier" db:"risk_tier"`
	RiskFactorsJSON          []byte                `json:"-" db:"risk_factors_json"`
	RiskScoredAt             *time.Time            `json:"risk_scored_at,omitempty" db:"risk_scored_at"`
	EPSSScore                *float64              `json:"epss_score,omitempty" db:"epss_score"`
	EPSSPercentile           *float64              `json:"epss_percentile,omitempty" db:"epss_percentile"`
	KEVListed                bool                  `json:"kev_listed" db:"kev_listed"`
	ThreatUpdatedAt          *time.Time            `json:"threat_updated_at,omitempty" db:"threat_updated_at"`
	SLADueAt                 *time.Time            `json:"sla_due_at,omitempty" db:"sla_due_at"`
	IsSLABreached            bool                  `json:"is_sla_breached" db:"is_sla_breached"`
	TriageStatus             TriageStatus          `json:"triage_status" db:"triage_status"`
	TriageDecidedAt          *time.Time            `json:"triage_decided_at,omitempty" db:"triage_decided_at"`
	TriageDecidedByUserID    *uuid.UUID            `json:"triage_decided_by_user_id,omitempty" db:"triage_decided_by_user_id"`
	TriageDecisionSource     *TriageDecisionSource `json:"triage_decision_source,omitempty" db:"triage_decision_source"`
	FindingType              string                `json:"finding_type,omitempty" db:"finding_type"`
	SourceEngine             string                `json:"source_engine,omitempty" db:"source_engine"`
	ExternalSource           string                `json:"external_source,omitempty" db:"external_source"`
	ExternalReference        string                `json:"external_reference,omitempty" db:"external_reference"`
	ReportedAt               *time.Time            `json:"reported_at,omitempty" db:"reported_at"`
	CreatedByUserID          *uuid.UUID            `json:"created_by_user_id,omitempty" db:"created_by_user_id"`
	BusinessImpact           string                `json:"business_impact,omitempty" db:"business_impact"`
	EvidenceJSON             []byte                `json:"-" db:"evidence_json"`
}

type FindingTeam struct {
	FindingID         uuid.UUID `json:"finding_id" db:"finding_id"`
	TeamID            uuid.UUID `json:"team_id" db:"team_id"`
	CodeownersPattern string    `json:"codeowners_pattern" db:"codeowners_pattern"`
}

type OrgMember struct {
	ID           uuid.UUID  `json:"id" db:"id"`
	OrgID        uuid.UUID  `json:"org_id" db:"org_id"`
	TenantID     uuid.UUID  `json:"tenant_id" db:"tenant_id"`
	GitHubUserID int64      `json:"github_user_id" db:"github_user_id"`
	GitHubLogin  string     `json:"github_login" db:"github_login"`
	Name         string     `json:"name" db:"name"`
	AvatarURL    string     `json:"avatar_url" db:"avatar_url"`
	UserID       *uuid.UUID `json:"user_id,omitempty" db:"user_id"`
	IsActive     bool       `json:"is_active" db:"is_active"`
	LastSyncedAt time.Time  `json:"last_synced_at" db:"last_synced_at"`
	CreatedAt    time.Time  `json:"created_at" db:"created_at"`
}

type FindingOwner struct {
	UserID      *uuid.UUID `json:"user_id,omitempty"`
	Name        string     `json:"name"`
	Email       string     `json:"email,omitempty"`
	AvatarURL   string     `json:"avatar_url,omitempty"`
	GitHubLogin string     `json:"github_login,omitempty"`
	TeamSlug    string     `json:"team_slug,omitempty"`
	Source      string     `json:"source"`
}

type AnalysisStatus string

const (
	AnalysisPending   AnalysisStatus = "pending"
	AnalysisRunning   AnalysisStatus = "running"
	AnalysisCompleted AnalysisStatus = "completed"
	AnalysisFailed    AnalysisStatus = "failed"
	AnalysisSkipped   AnalysisStatus = "skipped"
)

type AnalysisTrigger string

const (
	AnalysisTriggerScan   AnalysisTrigger = "scan"
	AnalysisTriggerManual AnalysisTrigger = "manual"
)

type CriticalityVerdict string

const (
	VerdictTrueCritical     CriticalityVerdict = "true_critical"
	VerdictFalsePositive    CriticalityVerdict = "false_positive"
	VerdictInformational    CriticalityVerdict = "informational"
	VerdictNeedsHumanReview CriticalityVerdict = "needs_human_review"
)

type ExploitabilityVerdict string

const (
	ExploitNone     ExploitabilityVerdict = "none"
	ExploitLow      ExploitabilityVerdict = "low"
	ExploitMedium   ExploitabilityVerdict = "medium"
	ExploitHigh     ExploitabilityVerdict = "high"
	ExploitCritical ExploitabilityVerdict = "critical"
)

type FindingAnalysis struct {
	ID                    uuid.UUID              `json:"id" db:"id"`
	TenantID              uuid.UUID              `json:"tenant_id" db:"tenant_id"`
	FindingID             uuid.UUID              `json:"finding_id" db:"finding_id"`
	ScanJobID             *uuid.UUID             `json:"scan_job_id,omitempty" db:"scan_job_id"`
	AnalysisStatus        AnalysisStatus         `json:"analysis_status" db:"analysis_status"`
	TriggerSource         AnalysisTrigger        `json:"trigger_source" db:"trigger_source"`
	LLMDispatchMode       LLMDispatchMode        `json:"llm_dispatch_mode" db:"llm_dispatch_mode"`
	LLMBatchID            *string                `json:"llm_batch_id,omitempty" db:"llm_batch_id"`
	LLMDispatchMeta       []byte                 `json:"llm_dispatch_meta,omitempty" db:"llm_dispatch_meta"`
	CriticalityVerdict    *CriticalityVerdict    `json:"criticality_verdict,omitempty" db:"criticality_verdict"`
	ExploitabilityVerdict *ExploitabilityVerdict `json:"exploitability_verdict,omitempty" db:"exploitability_verdict"`
	Confidence            *float64               `json:"confidence,omitempty" db:"confidence"`
	Reasoning             string                 `json:"reasoning" db:"reasoning"`
	ExploitationPath      string                 `json:"exploitation_path" db:"exploitation_path"`
	RemediationPath       string                 `json:"remediation_path" db:"remediation_path"`
	ModelName             *string                `json:"model_name,omitempty" db:"model_name"`
	PromptVersion         *string                `json:"prompt_version,omitempty" db:"prompt_version"`
	InputHash             *string                `json:"input_hash,omitempty" db:"input_hash"`
	ErrorMsg              *string                `json:"error_msg,omitempty" db:"error_msg"`
	StartedAt             *time.Time             `json:"started_at,omitempty" db:"started_at"`
	CompletedAt           *time.Time             `json:"completed_at,omitempty" db:"completed_at"`
	CreatedAt             time.Time              `json:"created_at" db:"created_at"`
}

type MaliciousIndicatorSource string

const (
	MaliciousIndicatorSourceOpenSSF MaliciousIndicatorSource = "openssf"
	MaliciousIndicatorSourceCustom  MaliciousIndicatorSource = "custom"
)

type MaliciousPackageIndicator struct {
	ID             uuid.UUID                `json:"id" db:"id"`
	Source         MaliciousIndicatorSource `json:"source" db:"source"`
	ExternalID     string                   `json:"external_id" db:"external_id"`
	Ecosystem      string                   `json:"ecosystem" db:"ecosystem"`
	PackageName    string                   `json:"package_name" db:"package_name"`
	PackageVersion string                   `json:"package_version" db:"package_version"`
	Summary        string                   `json:"summary" db:"summary"`
	Details        string                   `json:"details" db:"details"`
	PublishedAt    *time.Time               `json:"published_at,omitempty" db:"published_at"`
	ModifiedAt     *time.Time               `json:"modified_at,omitempty" db:"modified_at"`
	WithdrawnAt    *time.Time               `json:"withdrawn_at,omitempty" db:"withdrawn_at"`
	ReferencesJSON []byte                   `json:"-" db:"references_json"`
	AffectedJSON   []byte                   `json:"-" db:"affected_json"`
	RawJSON        []byte                   `json:"-" db:"raw_json"`
	LastSyncedAt   time.Time                `json:"last_synced_at" db:"last_synced_at"`
	CreatedAt      time.Time                `json:"created_at" db:"created_at"`
	UpdatedAt      time.Time                `json:"updated_at" db:"updated_at"`
}

type DependencyScope string

const (
	DependencyScopeDirect     DependencyScope = "direct"
	DependencyScopeTransitive DependencyScope = "transitive"
	DependencyScopeUnknown    DependencyScope = "unknown"
)

type PackageInventorySource string

const (
	PackageInventorySourceScan   PackageInventorySource = "scan"
	PackageInventorySourceSBOM   PackageInventorySource = "sbom"
	PackageInventorySourceManual PackageInventorySource = "manual"
)

type PackageInventory struct {
	ID              uuid.UUID              `json:"id" db:"id"`
	TenantID        uuid.UUID              `json:"tenant_id" db:"tenant_id"`
	RepoID          uuid.UUID              `json:"repo_id" db:"repo_id"`
	ManifestID      *uuid.UUID             `json:"manifest_id,omitempty" db:"manifest_id"`
	FindingID       *uuid.UUID             `json:"finding_id,omitempty" db:"finding_id"`
	Ecosystem       string                 `json:"ecosystem" db:"ecosystem"`
	PackageName     string                 `json:"package_name" db:"package_name"`
	PackageVersion  string                 `json:"package_version" db:"package_version"`
	DependencyScope DependencyScope        `json:"dependency_scope" db:"dependency_scope"`
	Source          PackageInventorySource `json:"source" db:"source"`
	FirstSeenAt     time.Time              `json:"first_seen_at" db:"first_seen_at"`
	LastSeenAt      time.Time              `json:"last_seen_at" db:"last_seen_at"`
	CreatedAt       time.Time              `json:"created_at" db:"created_at"`
	UpdatedAt       time.Time              `json:"updated_at" db:"updated_at"`
}

type SupplyChainSignalType string

const (
	SignalTypeMaliciousPackage    SupplyChainSignalType = "malicious_package"
	SignalTypeTyposquat           SupplyChainSignalType = "typosquat"
	SignalTypeDependencyConfusion SupplyChainSignalType = "dependency_confusion"
	SignalTypeSuspiciousBehavior  SupplyChainSignalType = "suspicious_behavior"
)

type SupplyChainSignalStatus string

const (
	SignalStatusOpen       SupplyChainSignalStatus = "open"
	SignalStatusTriaged    SupplyChainSignalStatus = "triaged"
	SignalStatusSuppressed SupplyChainSignalStatus = "suppressed"
	SignalStatusResolved   SupplyChainSignalStatus = "resolved"
)

type SupplyChainSignal struct {
	ID                 uuid.UUID               `json:"id" db:"id"`
	TenantID           uuid.UUID               `json:"tenant_id" db:"tenant_id"`
	RepoID             *uuid.UUID              `json:"repo_id,omitempty" db:"repo_id"`
	PackageInventoryID *uuid.UUID              `json:"package_inventory_id,omitempty" db:"package_inventory_id"`
	FindingID          *uuid.UUID              `json:"finding_id,omitempty" db:"finding_id"`
	IndicatorID        *uuid.UUID              `json:"indicator_id,omitempty" db:"indicator_id"`
	SignalType         SupplyChainSignalType   `json:"signal_type" db:"signal_type"`
	Status             SupplyChainSignalStatus `json:"status" db:"status"`
	Severity           Severity                `json:"severity" db:"severity"`
	PackageEcosystem   string                  `json:"package_ecosystem" db:"package_ecosystem"`
	PackageName        string                  `json:"package_name" db:"package_name"`
	PackageVersion     string                  `json:"package_version" db:"package_version"`
	SignalHash         string                  `json:"signal_hash" db:"signal_hash"`
	Confidence         *float64                `json:"confidence,omitempty" db:"confidence"`
	Reasoning          string                  `json:"reasoning" db:"reasoning"`
	MetadataJSON       []byte                  `json:"-" db:"metadata_json"`
	FirstSeenAt        time.Time               `json:"first_seen_at" db:"first_seen_at"`
	LastSeenAt         time.Time               `json:"last_seen_at" db:"last_seen_at"`
	ResolvedAt         *time.Time              `json:"resolved_at,omitempty" db:"resolved_at"`
	CreatedAt          time.Time               `json:"created_at" db:"created_at"`
	UpdatedAt          time.Time               `json:"updated_at" db:"updated_at"`
}

type DynamicAnalysisEngine string

const (
	DynamicAnalysisEnginePackageAnalysis DynamicAnalysisEngine = "package_analysis"
	DynamicAnalysisEngineSandbox         DynamicAnalysisEngine = "sandbox"
	DynamicAnalysisEngineOSV             DynamicAnalysisEngine = "osv"
	DynamicAnalysisEngineCustom          DynamicAnalysisEngine = "custom"
)

type DynamicAnalysisStatus string

const (
	DynamicAnalysisQueued    DynamicAnalysisStatus = "queued"
	DynamicAnalysisRunning   DynamicAnalysisStatus = "running"
	DynamicAnalysisCompleted DynamicAnalysisStatus = "completed"
	DynamicAnalysisFailed    DynamicAnalysisStatus = "failed"
	DynamicAnalysisSkipped   DynamicAnalysisStatus = "skipped"
)

type DynamicAnalysisVerdict string

const (
	DynamicAnalysisVerdictMalicious    DynamicAnalysisVerdict = "malicious"
	DynamicAnalysisVerdictSuspicious   DynamicAnalysisVerdict = "suspicious"
	DynamicAnalysisVerdictBenign       DynamicAnalysisVerdict = "benign"
	DynamicAnalysisVerdictInconclusive DynamicAnalysisVerdict = "inconclusive"
)

type PackageDynamicAnalysisRun struct {
	ID               uuid.UUID               `json:"id" db:"id"`
	TenantID         uuid.UUID               `json:"tenant_id" db:"tenant_id"`
	SignalID         *uuid.UUID              `json:"signal_id,omitempty" db:"signal_id"`
	PackageEcosystem string                  `json:"package_ecosystem" db:"package_ecosystem"`
	PackageName      string                  `json:"package_name" db:"package_name"`
	PackageVersion   string                  `json:"package_version" db:"package_version"`
	Engine           DynamicAnalysisEngine   `json:"engine" db:"engine"`
	Status           DynamicAnalysisStatus   `json:"status" db:"status"`
	Verdict          *DynamicAnalysisVerdict `json:"verdict,omitempty" db:"verdict"`
	RiskScore        *float64                `json:"risk_score,omitempty" db:"risk_score"`
	Summary          string                  `json:"summary" db:"summary"`
	ErrorMsg         *string                 `json:"error_msg,omitempty" db:"error_msg"`
	ReportJSON       []byte                  `json:"-" db:"report_json"`
	StartedAt        *time.Time              `json:"started_at,omitempty" db:"started_at"`
	CompletedAt      *time.Time              `json:"completed_at,omitempty" db:"completed_at"`
	CreatedAt        time.Time               `json:"created_at" db:"created_at"`
	UpdatedAt        time.Time               `json:"updated_at" db:"updated_at"`
}
