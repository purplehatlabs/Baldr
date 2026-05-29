import { api } from './client'
import type { Finding } from './findings'

export interface Team {
  id: string
  org_id: string
  github_team_slug: string
  display_name: string
  critical: number
  high: number
  medium: number
  low: number
  total: number
}

export async function listTeams(): Promise<Team[]> {
  const { data } = await api.get<Team[]>('/api/v1/teams')
  return data
}

export async function getTeamFindings(teamId: string): Promise<Finding[]> {
  const { data } = await api.get<Finding[]>(`/api/v1/teams/${teamId}/findings`)
  return data
}

export interface TeamMember {
  id: string
  github_login: string
  name: string
  avatar_url: string
  user_id?: string
  is_active: boolean
}

export async function getTeamMembers(teamId: string): Promise<TeamMember[]> {
  const { data } = await api.get<TeamMember[]>(`/api/v1/teams/${teamId}/members`)
  return data
}
