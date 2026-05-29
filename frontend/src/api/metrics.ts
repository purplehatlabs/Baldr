import { api } from './client'

export interface OverviewMetrics {
  open_critical: number
  open_high: number
  mttr_high_plus_hours: number
  sla_breach_rate: number
  scan_coverage_rate: number
  critical_without_owner: number
  total_findings: number
  needs_review: number
  auto_triaged: number
  auto_triaged_rate: number
  noise_reduction_rate: number
  confirmed_total: number
  dismissed_total: number
  reachable_open: number
}

export interface MetricTrendPoint {
  date: string
  new_findings: number
  fixed_findings: number
}

export interface MetricsTrendsResponse {
  days: number
  trend: MetricTrendPoint[]
}

export interface RiskTrendPoint {
  date: string
  open_critical: number
  open_high: number
  sla_breach_rate: number
  new_findings: number
  fixed_findings: number
}

export interface RiskTrendResponse {
  days: number
  trend: RiskTrendPoint[]
}

export interface RepoRiskRow {
  repo_id: string
  repo_full_name: string
  is_internet_exposed: boolean | null
  open_critical: number
  open_high: number
  open_total: number
  max_risk_score: number
  sla_breach_count: number
  reachable_count: number
}

export interface TeamRiskRow {
  team_id: string
  team_slug: string
  display_name: string
  open_critical: number
  open_high: number
  open_total: number
  max_risk_score: number
  sla_breach_count: number
  sla_breach_rate: number
}

export async function getMetricsOverview(): Promise<OverviewMetrics> {
  const { data } = await api.get<OverviewMetrics>('/api/v1/metrics/overview')
  return data
}

export async function getMetricsTrends(days = 30): Promise<MetricsTrendsResponse> {
  const { data } = await api.get<MetricsTrendsResponse>('/api/v1/metrics/trends', {
    params: { days },
  })
  return data
}

export async function getRiskTrend(days = 30): Promise<RiskTrendResponse> {
  const { data } = await api.get<RiskTrendResponse>('/api/v1/metrics/risk-trend', {
    params: { days },
  })
  return data
}

export async function getRiskByRepo(limit = 10): Promise<RepoRiskRow[]> {
  const { data } = await api.get<{ items: RepoRiskRow[] }>('/api/v1/metrics/risk-by-repo', {
    params: { limit },
  })
  return data.items ?? []
}

export async function getRiskByTeam(limit = 10): Promise<TeamRiskRow[]> {
  const { data } = await api.get<{ items: TeamRiskRow[] }>('/api/v1/metrics/risk-by-team', {
    params: { limit },
  })
  return data.items ?? []
}
