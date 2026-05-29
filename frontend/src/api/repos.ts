import { api } from './client'

export interface Repo {
  id: string
  org_id: string
  github_repo_id: number
  full_name: string
  default_branch: string
  is_archived: boolean
  is_monorepo: boolean
  is_internet_exposed: boolean | null
  exposure_source?: 'manual' | 'auto_discovery' | null
  exposure_updated_at?: string | null
  asset_criticality: 'low' | 'medium' | 'high' | 'critical'
  data_sensitivity: 'public' | 'internal' | 'confidential' | 'restricted'
  environment: 'dev' | 'staging' | 'prod'
  last_scanned_at: string | null
  latest_scan_status?: ScanJob['status'] | null
  created_at: string
}

export interface ScanJob {
  id: string
  repo_id: string
  status: 'pending' | 'running' | 'completed' | 'failed'
  triggered_by: 'scheduled' | 'manual' | 'webhook'
  commit_sha: string
  started_at: string | null
  completed_at: string | null
  error_msg?: string
  created_at: string
}

export function isRepoScanActive(status?: ScanJob['status'] | null): boolean {
  return status === 'pending' || status === 'running'
}

export function getScanApiErrorMessage(err: unknown): string | null {
  const axiosErr = err as { response?: { status?: number; data?: { code?: string; error?: string } } }
  const code = axiosErr.response?.data?.code ?? axiosErr.response?.data?.error
  if (axiosErr.response?.status === 409 && code === 'scan_already_queued_or_running') {
    return 'This repository already has a scan queued or running.'
  }
  if (axiosErr.response?.status === 409 && code === 'scan_blocked_missing_internet_exposure') {
    return 'Set the repository exposure before scanning.'
  }
  return null
}

export async function listRepos(
  orgId?: string,
  exposureStatus?: 'pending' | 'internet' | 'internal',
): Promise<Repo[]> {
  const params: Record<string, string> = {}
  if (orgId) params.org_id = orgId
  if (exposureStatus) params.exposure_status = exposureStatus
  const { data } = await api.get<Repo[]>('/api/v1/repos', { params })
  return data
}

export async function triggerScan(repoId: string): Promise<void> {
  await api.post(`/api/v1/repos/${repoId}/scan`)
}

export interface RescanAllResponse {
  enqueued: number
  total: number
  blocked: number
  blocked_repos: Array<{ repo_id: string; reason: string }>
  skipped?: number
  skipped_repos?: Array<{ repo_id: string; reason: string }>
}

export async function rescanAllRepos(orgId?: string): Promise<RescanAllResponse> {
  const params = orgId ? { org_id: orgId } : {}
  const { data } = await api.post<RescanAllResponse>('/api/v1/repos/rescan-all', null, { params })
  return data
}

export async function listScanJobs(repoId: string): Promise<ScanJob[]> {
  const { data } = await api.get<ScanJob[]>(`/api/v1/repos/${repoId}/jobs`)
  return data
}

export async function updateRepoExposure(
  repoId: string,
  input: { is_internet_exposed: boolean; exposure_source: 'manual' | 'auto_discovery' },
): Promise<void> {
  await api.patch(`/api/v1/repos/${repoId}/exposure`, input)
}
