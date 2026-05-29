import { api } from './client'

export interface GitHubAppStatus {
  configured: boolean
  app_id?: number
  updated_at?: string
}

export interface UpdateGitHubAppInput {
  app_id: number
  private_key: string
}

export async function getGitHubAppStatus(): Promise<GitHubAppStatus> {
  const { data } = await api.get<GitHubAppStatus>('/api/v1/settings/github-app')
  return data
}

export async function updateGitHubApp(input: UpdateGitHubAppInput): Promise<void> {
  await api.put('/api/v1/settings/github-app', input)
}

export async function deleteGitHubApp(): Promise<void> {
  await api.delete('/api/v1/settings/github-app')
}

export interface LLMStatus {
  configured: boolean
  base_url?: string
  model?: string
  agentic_model?: string
  translation_model?: string
  batch_enabled: boolean
  has_api_key: boolean
  timeout_seconds?: number
  auto_analysis_min_severity: 'critical' | 'high' | 'medium'
  updated_at?: string
}

// api_key semantics:
// - undefined / not sent  -> preserve existing stored key
// - empty string          -> clear the stored key
// - non-empty string      -> replace with the new key
export interface UpdateLLMInput {
  base_url: string
  model: string
  agentic_model?: string
  translation_model?: string
  batch_enabled?: boolean
  api_key?: string
  timeout_seconds?: number
  auto_analysis_min_severity?: 'critical' | 'high' | 'medium'
}

export async function getLLMStatus(): Promise<LLMStatus> {
  const { data } = await api.get<LLMStatus>('/api/v1/settings/llm')
  return data
}

export async function updateLLM(input: UpdateLLMInput): Promise<void> {
  await api.put('/api/v1/settings/llm', input)
}

export async function deleteLLM(): Promise<void> {
  await api.delete('/api/v1/settings/llm')
}
