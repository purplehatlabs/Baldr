import { api } from './client'

export interface SlackIntegration {
  enabled: boolean
  webhook_url?: string
  channel?: string
  updated_at?: string
}

export interface JiraIntegration {
  enabled: boolean
  base_url?: string
  project_key?: string
  email?: string
  api_token?: string
  updated_at?: string
}

export interface GitHubChecksIntegration {
  enabled: boolean
  check_name?: string
  only_on_default_branch?: boolean
  updated_at?: string
}

export interface SlackIntegrationInput {
  enabled: boolean
  webhook_url?: string
  channel?: string
}

export interface JiraIntegrationInput {
  enabled: boolean
  base_url?: string
  project_key?: string
  email?: string
  api_token?: string
}

export interface GitHubChecksInput {
  enabled: boolean
  check_name?: string
  only_on_default_branch?: boolean
}

interface IntegrationEnvelope {
  integration_type: string
  enabled: boolean
  config: Record<string, unknown>
  updated_at?: string
}

export async function getSlackIntegration(): Promise<SlackIntegration> {
  const { data } = await api.get<IntegrationEnvelope>('/api/v1/integrations/slack')
  return {
    enabled: data.enabled,
    webhook_url: typeof data.config?.webhook_url === 'string' ? data.config.webhook_url : undefined,
    channel: typeof data.config?.channel === 'string' ? data.config.channel : undefined,
    updated_at: data.updated_at,
  }
}

export async function updateSlackIntegration(input: SlackIntegrationInput): Promise<void> {
  await api.put('/api/v1/integrations/slack', {
    enabled: input.enabled,
    config: {
      webhook_url: input.webhook_url,
      channel: input.channel,
    },
  })
}

export async function deleteSlackIntegration(): Promise<void> {
  await api.delete('/api/v1/integrations/slack')
}

export async function getJiraIntegration(): Promise<JiraIntegration> {
  const { data } = await api.get<IntegrationEnvelope>('/api/v1/integrations/jira')
  return {
    enabled: data.enabled,
    base_url: typeof data.config?.base_url === 'string' ? data.config.base_url : undefined,
    project_key: typeof data.config?.project_key === 'string' ? data.config.project_key : undefined,
    email: typeof data.config?.email === 'string' ? data.config.email : undefined,
    api_token: typeof data.config?.api_token === 'string' ? data.config.api_token : undefined,
    updated_at: data.updated_at,
  }
}

export async function updateJiraIntegration(input: JiraIntegrationInput): Promise<void> {
  await api.put('/api/v1/integrations/jira', {
    enabled: input.enabled,
    config: {
      base_url: input.base_url,
      project_key: input.project_key,
      email: input.email,
      api_token: input.api_token,
    },
  })
}

export async function deleteJiraIntegration(): Promise<void> {
  await api.delete('/api/v1/integrations/jira')
}

export async function getGitHubChecksIntegration(): Promise<GitHubChecksIntegration> {
  const { data } = await api.get<IntegrationEnvelope>('/api/v1/integrations/github-checks')
  return {
    enabled: data.enabled,
    check_name: typeof data.config?.check_name === 'string' ? data.config.check_name : undefined,
    only_on_default_branch:
      typeof data.config?.only_on_default_branch === 'boolean'
        ? data.config.only_on_default_branch
        : undefined,
    updated_at: data.updated_at,
  }
}

export async function updateGitHubChecksIntegration(input: GitHubChecksInput): Promise<void> {
  await api.put('/api/v1/integrations/github-checks', {
    enabled: input.enabled,
    config: {
      check_name: input.check_name,
      only_on_default_branch: input.only_on_default_branch,
    },
  })
}

export async function deleteGitHubChecksIntegration(): Promise<void> {
  await api.delete('/api/v1/integrations/github-checks')
}
