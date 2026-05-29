import { api } from './client'

export interface Org {
  id: string
  tenant_id: string
  github_org_login: string
  github_app_installation_id: number | null
  scan_cron: string
  is_active: boolean
  created_at: string
}

export interface CreateOrgInput {
  github_org_login: string
  github_app_installation_id?: number
  scan_cron?: string
}

export async function listOrgs(): Promise<Org[]> {
  const { data } = await api.get<Org[]>('/api/v1/orgs')
  return data
}

export async function createOrg(input: CreateOrgInput): Promise<Org> {
  const { data } = await api.post<Org>('/api/v1/orgs', input)
  return data
}

export async function deleteOrg(id: string): Promise<void> {
  await api.delete(`/api/v1/orgs/${id}`)
}

export interface GitHubRepo {
  github_repo_id: number
  full_name: string
  description: string
  default_branch: string
  private: boolean
  language: string
  updated_at: string
  is_tracked: boolean
  tracked_repo_id?: string
  last_scanned_at?: string
  latest_scan_status?: 'pending' | 'running' | 'completed' | 'failed'
  is_internet_exposed?: boolean | null
}

export interface BrowsePage {
  repos: GitHubRepo[]
  page: number
  per_page: number
  next_page: number
}

export interface ScanGitHubRepoInput {
  github_repo_id: number
  full_name: string
  default_branch: string
}

export interface ScanBatchResponse {
  enqueued: number
  failed: number
  blocked: number
  skipped?: number
  repo_ids: string[]
  blocked_repos: Array<{ repo_id: string; reason: string }>
  skipped_repos?: Array<{ repo_id: string; reason: string }>
}

export interface SyncResponse {
  total_from_github: number
  imported: number
  updated: number
}

export interface MembershipSyncResponse {
  org_members_upserted: number
  org_members_inactive: number
  team_links_upserted: number
  team_links_removed: number
  teams_processed: number
}

export async function listGitHubRepos(
  orgId: string,
  page = 1,
  perPage = 50,
): Promise<BrowsePage> {
  const { data } = await api.get<BrowsePage>(
    `/api/v1/orgs/${orgId}/github-repos`,
    { params: { page, per_page: perPage } },
  )
  return data
}

export async function scanGitHubRepo(
  orgId: string,
  input: ScanGitHubRepoInput,
): Promise<{ repo_id: string }> {
  const { data } = await api.post<{ repo_id: string }>(
    `/api/v1/orgs/${orgId}/github-repos/scan`,
    input,
  )
  return data
}

export async function scanGitHubReposBatch(
  orgId: string,
  repos: ScanGitHubRepoInput[],
): Promise<ScanBatchResponse> {
  const { data } = await api.post<ScanBatchResponse>(
    `/api/v1/orgs/${orgId}/github-repos/scan-batch`,
    { repos },
  )
  return data
}

export async function syncOrgRepos(orgId: string): Promise<SyncResponse> {
  const { data } = await api.post<SyncResponse>(`/api/v1/orgs/${orgId}/sync`)
  return data
}

export async function syncOrgMemberships(orgId: string): Promise<MembershipSyncResponse> {
  const { data } = await api.post<MembershipSyncResponse>(`/api/v1/orgs/${orgId}/sync-memberships`)
  return data
}
