import { api } from './client'
import { normalizeLocale, type AppLocale } from '@/i18n/languages'

export type AppLanguage = AppLocale

export interface User {
  id: string
  tenant_id: string
  email: string
  name: string
  avatar_url: string
  role: 'owner' | 'admin' | 'member'
  language?: AppLanguage
  created_at: string
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

export function getGoogleLoginURL(): string {
  return '/auth/google'
}

export function getGitHubLoginURL(): string {
  return '/auth/github'
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
