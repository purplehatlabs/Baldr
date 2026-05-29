import { api } from './client'
import type { ScanJob } from './repos'

export interface ScanJobWithRepo extends ScanJob {
  repo_full_name: string
}

export interface ScanJobsListResponse {
  items: ScanJobWithRepo[]
  page: number
  per_page: number
  total: number
}

export interface ScanJobsSummary {
  pending: number
  running: number
  total_active: number
}

export type ScanJobStatus = ScanJob['status']

export async function listScanJobs(params?: {
  status?: ScanJobStatus
  repo_id?: string
  page?: number
  per_page?: number
}): Promise<ScanJobsListResponse> {
  const { data } = await api.get<ScanJobsListResponse>('/api/v1/scan-jobs', { params })
  return data
}

export async function getScanJobsSummary(): Promise<ScanJobsSummary> {
  const { data } = await api.get<ScanJobsSummary>('/api/v1/scan-jobs/summary')
  return data
}
