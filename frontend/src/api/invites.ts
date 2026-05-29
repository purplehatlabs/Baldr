import { api } from './client'
import type { UserRole } from './auth'

export type InviteStatus = 'pending' | 'accepted' | 'revoked' | 'expired'

export interface TenantInvite {
  id: string
  email: string
  role: UserRole
  status: InviteStatus
  expires_at: string
  created_at: string
  invite_url?: string
}

export interface InvitesListResponse {
  invites: TenantInvite[]
}

export interface CreateInviteInput {
  email: string
  role?: UserRole
}

export interface AcceptInviteResponse {
  ok: boolean
  active_tenant_id: string
  role: UserRole
}

export async function listInvites(): Promise<TenantInvite[]> {
  const { data } = await api.get<InvitesListResponse>('/api/v1/invites')
  return data.invites ?? []
}

export async function createInvite(input: CreateInviteInput): Promise<TenantInvite> {
  const { data } = await api.post<TenantInvite>('/api/v1/invites', input)
  return data
}

export async function revokeInvite(inviteId: string): Promise<void> {
  await api.delete(`/api/v1/invites/${inviteId}`)
}

export async function acceptInvite(token: string): Promise<AcceptInviteResponse> {
  const { data } = await api.post<AcceptInviteResponse>(`/api/v1/invites/${token}/accept`)
  return data
}
