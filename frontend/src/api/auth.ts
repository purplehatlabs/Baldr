import { api } from './client'
import { normalizeLocale, type AppLocale } from '@/i18n/languages'

export type AppLanguage = AppLocale

export type UserRole = 'owner' | 'admin' | 'member'

export interface User {
  id: string
  tenant_id: string
  email: string
  name: string
  avatar_url: string
  role: UserRole
  language?: AppLanguage
  created_at: string
}

export interface TenantSummary {
  tenant_id: string
  tenant_name: string
  tenant_slug: string
  role: UserRole
  status: 'active' | 'inactive'
  is_active: boolean
}

export interface AuthTenantsResponse {
  tenants: TenantSummary[]
  active_tenant_id: string
}

export interface SwitchTenantResponse {
  ok: boolean
  active_tenant_id: string
  role: UserRole
}

export interface UserPreferences {
  language: AppLanguage
}

export async function getMe(): Promise<User> {
  const { data } = await api.get<User>('/auth/me')
  return {
    ...data,
    language: normalizeLocale(data.language),
  }
}

export async function updateUserPreferences(input: UserPreferences): Promise<UserPreferences> {
  const { data } = await api.patch<UserPreferences>('/auth/me/preferences', {
    language: normalizeLocale(input.language),
  })
  return {
    language: normalizeLocale(data.language),
  }
}

export async function logout(): Promise<void> {
  await api.post('/auth/logout')
}

function withNextQuery(path: string, nextPath?: string): string {
  if (!nextPath) {
    return path
  }

  return `${path}?next=${encodeURIComponent(nextPath)}`
}

export function getGoogleLoginURL(nextPath?: string): string {
  return withNextQuery('/auth/google', nextPath)
}

export function getGitHubLoginURL(nextPath?: string): string {
  return withNextQuery('/auth/github', nextPath)
}

export function isGitHubSSOEnabled(): boolean {
  return import.meta.env.VITE_GITHUB_SSO_ENABLED !== 'false'
}

export function isGoogleSSOEnabled(): boolean {
  return import.meta.env.VITE_GOOGLE_SSO_ENABLED !== 'false'
}

export function isDevAuthEnabled(): boolean {
  return import.meta.env.VITE_DEV_AUTH_ENABLED === 'true'
}

export async function devLogin(email: string, name?: string): Promise<void> {
  await api.post('/auth/dev/login', { email, name })
}

export async function getAuthTenants(): Promise<AuthTenantsResponse> {
  const { data } = await api.get<AuthTenantsResponse>('/auth/tenants')
  return data
}

export async function switchTenant(tenantId: string): Promise<SwitchTenantResponse> {
  const { data } = await api.post<SwitchTenantResponse>('/auth/switch-tenant', {
    tenant_id: tenantId,
  })
  return data
}
