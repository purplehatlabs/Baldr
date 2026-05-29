import { api } from './client'

export interface DashboardSummary {
  findings_by_severity: {
    critical: number
    high: number
    medium: number
    low: number
    unknown: number
  }
  total_repos: number
  total_findings: number
  open_findings: number
  fixed_findings: number
}

export async function getDashboard(): Promise<DashboardSummary> {
  const { data } = await api.get<DashboardSummary>('/api/v1/dashboard')
  return data
}
