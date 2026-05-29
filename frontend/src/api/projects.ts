import { api } from './client'

export interface Project {
  id: string
  repo: string
  last_scanned_at: string | null
  open_critical: number
  open_high: number
  open_total: number
}

export interface ProjectsListResponse {
  items: Project[]
  page: number
  per_page: number
  total: number
}

export interface ProjectDetail {
  id: string
  repo: string
  default_branch: string
  is_archived: boolean
  last_scanned_at: string | null
  open_critical: number
  open_high: number
  open_total: number
  fixed_total: number
}

export async function listProjects(page = 1, perPage = 20): Promise<ProjectsListResponse> {
  const { data } = await api.get<ProjectsListResponse>('/api/v1/projects', {
    params: {
      page,
      per_page: perPage,
    },
  })
  return data
}

export async function getProject(id: string): Promise<ProjectDetail> {
  const { data } = await api.get<ProjectDetail>(`/api/v1/projects/${id}`)
  return data
}
