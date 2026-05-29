import { api } from './client'

export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'unknown'
export type SourceEngine = 'osv' | 'dataset' | 'guarddog' | 'openssf_pa' | 'manual'
export type FindingStatus = 'open' | 'suppressed' | 'fixed'
export type TriageStatus = 'new' | 'needs_review' | 'confirmed' | 'dismissed'
export type TriageDecisionSource = 'auto_ai' | 'manual' | 'system'
export type SortOrder = 'asc' | 'desc'
export type FindingSortField =
  | 'severity'
  | 'status'
  | 'last_seen_at'
  | 'first_seen_at'
  | 'cvss_score'
  | 'package_name'
  | 'risk_score'

export type ReachabilityStatus = 'reachable' | 'unknown' | 'unreachable'
export type RiskTier = 'critical' | 'high' | 'medium' | 'low'

export interface RiskFactor {
  name: string
  points: number
  detail?: string
}

export interface ReachabilityEvidence {
  method?: string
  ecosystem?: string
  package_name?: string
  matched_in?: string[]
  reason?: string
}

export type AnalysisStatus = 'pending' | 'running' | 'completed' | 'failed' | 'skipped'
export type CriticalityVerdict = 'true_critical' | 'false_positive' | 'informational' | 'needs_human_review'
export type ExploitabilityVerdict = 'none' | 'low' | 'medium' | 'high' | 'critical'

export interface FindingTeam {
  id: string
  slug: string
  display_name: string
}

export interface FindingOwner {
  user_id?: string
  name: string
  email?: string
  avatar_url?: string
  github_login?: string
  team_slug?: string
  source: 'linked_user' | 'org_member' | 'team_fallback' | string
}

export interface Finding {
  id: string
  tenant_id?: string
  scan_job_id?: string
  manifest_id?: string
  osv_id: string
  package_name: string
  package_version: string
  fixed_version?: string
  severity: Severity
  cvss_score?: number
  summary: string
  details: string
  status: FindingStatus
  first_seen_at: string
  last_seen_at: string
  finding_type?: string
  source_engine?: SourceEngine
  external_source?: string
  external_reference?: string
  reported_at?: string
  created_by_user_id?: string
  business_impact?: string
  evidence?: Record<string, unknown>
  reachability_status?: ReachabilityStatus
  reachability_confidence?: number
  reachability_evidence?: ReachabilityEvidence
  reachability_analyzed_at?: string
  risk_score?: number
  risk_tier?: RiskTier
  risk_factors?: RiskFactor[]
  risk_scored_at?: string
  epss_score?: number
  epss_percentile?: number
  kev_listed?: boolean
  threat_updated_at?: string
  sla_due_at?: string
  is_sla_breached?: boolean
  triage_status?: TriageStatus
  triage_decided_at?: string
  triage_decided_by_user_id?: string
  triage_decision_source?: TriageDecisionSource
  repo_full_name: string
  manifest_path: string
  teams: FindingTeam[]
  owners?: FindingOwner[]
  ai_analysis_status?: AnalysisStatus
  ai_criticality_verdict?: CriticalityVerdict
  ai_exploitability_verdict?: ExploitabilityVerdict
  ai_confidence?: number
  ai_reasoning?: string
  ai_exploitation_path?: string
  ai_remediation_path?: string
  ai_reasoning_display?: string
  ai_exploitation_path_display?: string
  ai_remediation_path_display?: string
  ai_analyzed_at?: string
  ai_analysis_error?: string
  ai_vulnerable_code_paths?: string[]
  has_contextual_analysis?: boolean
}

export interface FindingsFilter {
  severity?: Severity
  status?: FindingStatus
  team_id?: string
  repo_id?: string
  reachability?: ReachabilityStatus
  risk_tier?: RiskTier
  sla_breached?: boolean
  exclude_exceptions?: boolean
  triage_queue?: 'pending'
  triage_status?: TriageStatus | string
  source_engine?: SourceEngine
  q?: string
  page?: number
  page_size?: number
  sort?: FindingSortField
  order?: SortOrder
}

export interface FindingsPage {
  items: Finding[]
  total: number
  page: number
  page_size: number
  total_pages: number
}

export type FindingBulkAction = 'assign' | 'suppress' | 'reopen' | 'mark_fixed' | 'reanalyze'

export interface BulkFindingsInput {
  ids: string[]
  action: FindingBulkAction
  assignee_user_id?: string
  note?: string
}

export interface BulkFindingsResult {
  updated: number
  failed: number
  action?: FindingBulkAction | string
  reanalyze_enqueued?: number
  reanalyze_already_queued?: number
  reanalyze_skipped_manual?: number
  reanalyze_failed?: number
}

function asRecord(value: unknown): Record<string, unknown> | null {
  if (!value || typeof value !== 'object') return null
  return value as Record<string, unknown>
}

function asFindingsArray(value: unknown): Finding[] {
  return Array.isArray(value) ? (value as Finding[]) : []
}

function asNumber(value: unknown, fallback: number): number {
  return typeof value === 'number' && Number.isFinite(value) ? value : fallback
}

function normalizeFindingsPage(data: unknown): FindingsPage {
  if (Array.isArray(data)) {
    return {
      items: data as Finding[],
      total: data.length,
      page: 1,
      page_size: data.length || 20,
      total_pages: 1,
    }
  }

  const record = asRecord(data)
  if (!record) {
    return { items: [], total: 0, page: 1, page_size: 20, total_pages: 0 }
  }

  const items = asFindingsArray(record.items ?? record.findings ?? record.results)
  const total = asNumber(record.total, items.length)
  const page = asNumber(record.page, 1)
  const pageSize = asNumber(record.page_size, items.length || 20)
  const totalPages = asNumber(
    record.total_pages,
    pageSize > 0 ? Math.ceil(total / pageSize) : 0,
  )

  return {
    items,
    total,
    page,
    page_size: pageSize,
    total_pages: totalPages,
  }
}

export async function listFindings(filter?: FindingsFilter): Promise<FindingsPage> {
  const params: Record<string, string | number | boolean | undefined> = { ...filter }
  if (filter?.sla_breached) {
    params.sla_breached = 'true'
  }
  const { data } = await api.get('/api/v1/findings', { params })
  return normalizeFindingsPage(data)
}

export async function listTopRisks(limit = 10, filter?: Pick<FindingsFilter, 'severity' | 'team_id' | 'repo_id' | 'reachability' | 'source_engine'>): Promise<Finding[]> {
  const { data } = await api.get<{ items: Finding[] }>('/api/v1/findings/top-risks', {
    params: { limit, ...filter },
  })
  return data.items ?? []
}

export async function getFinding(id: string): Promise<Finding> {
  const { data } = await api.get<Finding>(`/api/v1/findings/${id}`)
  return data
}

export interface CreateManualFindingInput {
  summary: string
  severity: Severity
  external_reference: string
  package_name?: string
  package_version?: string
  external_source?: string
  details?: string
  business_impact?: string
  evidence?: Record<string, unknown>
  cvss_score?: number
  sla_due_at?: string
  reported_at?: string
}

export async function createManualFinding(input: CreateManualFindingInput): Promise<{ id: string }> {
  const { data } = await api.post<{ id: string }>('/api/v1/findings/manual', input)
  return data
}

export async function updateFindingStatus(id: string, status: FindingStatus): Promise<void> {
  await api.patch(`/api/v1/findings/${id}`, { status })
}

export async function confirmFindingTriage(id: string): Promise<void> {
  await api.post(`/api/v1/findings/${id}/triage/confirm`)
}

export async function dismissFindingTriage(id: string): Promise<void> {
  await api.post(`/api/v1/findings/${id}/triage/dismiss`)
}

export async function reopenFindingTriage(id: string): Promise<void> {
  await api.post(`/api/v1/findings/${id}/triage/reopen`)
}

export async function analyzeFinding(id: string): Promise<{ message: string; finding_id: string; analysis_id: string }> {
  const { data } = await api.post<{ message: string; finding_id: string; analysis_id: string }>(
    `/api/v1/findings/${id}/analyze`,
  )
  return data
}

export async function bulkUpdateFindings(input: BulkFindingsInput): Promise<BulkFindingsResult> {
  const { data } = await api.post('/api/v1/findings/bulk/actions', {
    action: input.action,
    finding_ids: input.ids,
    assigned_user_id: input.assignee_user_id,
    note: input.note,
  })
  const record = asRecord(data)

  return {
    updated: asNumber(record?.matched_count, input.ids.length),
    failed: asNumber(record?.failed, 0),
    action: typeof record?.action === 'string' ? record.action : input.action,
    reanalyze_enqueued: asNumber(record?.reanalyze_enqueued, 0),
    reanalyze_already_queued: asNumber(record?.reanalyze_already_queued, 0),
    reanalyze_skipped_manual: asNumber(record?.reanalyze_skipped_manual, 0),
    reanalyze_failed: asNumber(record?.reanalyze_failed, 0),
  }
}
