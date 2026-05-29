import { api } from './client'
import type { UserRole } from './auth'

export type MembershipStatus = 'active' | 'inactive'

export interface TenantMember {
  membership_id: string
  user_id: string
  email: string
  name: string
  avatar_url: string
  role: UserRole
  status: MembershipStatus
  created_at: string
  updated_at: string
}

export interface MembersListResponse {
  members: TenantMember[]
}

export interface UpdateMemberInput {
  role?: UserRole
  status?: MembershipStatus
}

export async function listMembers(): Promise<TenantMember[]> {
  const { data } = await api.get<MembersListResponse>('/api/v1/members')
  return data.members ?? []
}

export async function updateMember(
  membershipId: string,
  input: UpdateMemberInput,
): Promise<TenantMember> {
  const { data } = await api.patch<TenantMember>(`/api/v1/members/${membershipId}`, input)
  return data
}
