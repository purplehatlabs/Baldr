import { api } from './client'
import type { Severity } from './findings'

export interface Policy {
  id: string
  name: string
  description?: string
  enabled: boolean
  severity_threshold?: Severity
  risk_score_threshold?: number
  sla_hours?: number
  created_at?: string
  updated_at?: string
}

interface BackendPolicyRule {
  rule_type: string
  field: string
  operator: string
  value?: Record<string, unknown>
}

interface BackendPolicy {
  id: string
  name: string
  description?: string
  is_enabled: boolean
  rules?: BackendPolicyRule[]
  created_at?: string
  updated_at?: string
}

export interface PolicyInput {
  name: string
  description?: string
  enabled: boolean
  severity_threshold?: Severity
  risk_score_threshold?: number
  sla_hours?: number
}

function asRecord(value: unknown): Record<string, unknown> | null {
  if (!value || typeof value !== 'object') return null
  return value as Record<string, unknown>
}

function asPoliciesArray(value: unknown): Policy[] {
  if (!Array.isArray(value)) return []
  return value.map((item) => {
    const policy = item as BackendPolicy
    const severityRule = policy.rules?.find((rule) => rule.rule_type === 'severity_threshold')
    const riskRule = policy.rules?.find((rule) => rule.rule_type === 'risk_score_threshold')
    const slaRule = policy.rules?.find((rule) => rule.rule_type === 'sla_hours')
    const severity = severityRule?.value?.severity as Severity | undefined
    const riskScore = riskRule?.value?.score
    const sla = slaRule?.value?.hours
    return {
      id: policy.id,
      name: policy.name,
      description: policy.description,
      enabled: Boolean(policy.is_enabled),
      severity_threshold: severity,
      risk_score_threshold: typeof riskScore === 'number' ? riskScore : undefined,
      sla_hours: typeof sla === 'number' ? sla : undefined,
      created_at: policy.created_at,
      updated_at: policy.updated_at,
    }
  })
}

export async function listPolicies(): Promise<Policy[]> {
  const { data } = await api.get('/api/v1/policies')
  if (Array.isArray(data)) return data as Policy[]
  const record = asRecord(data)
  return asPoliciesArray(record?.items ?? record?.policies ?? record?.results)
}

function buildPolicyRules(input: PolicyInput): BackendPolicyRule[] {
  const rules: BackendPolicyRule[] = []
  if (input.severity_threshold) {
    rules.push({
      rule_type: 'severity_threshold',
      field: 'severity',
      operator: 'gte',
      value: { severity: input.severity_threshold },
    })
  }
  if (typeof input.risk_score_threshold === 'number') {
    rules.push({
      rule_type: 'risk_score_threshold',
      field: 'risk_score',
      operator: 'gte',
      value: { score: input.risk_score_threshold },
    })
  }
  if (typeof input.sla_hours === 'number') {
    rules.push({
      rule_type: 'sla_hours',
      field: 'age_hours',
      operator: 'gt',
      value: { hours: input.sla_hours },
    })
  }
  return rules
}

export async function createPolicy(input: PolicyInput): Promise<Policy> {
  const rules = buildPolicyRules(input)
  const { data } = await api.post<{ id: string }>('/api/v1/policies', {
    name: input.name,
    description: input.description ?? '',
    is_enabled: input.enabled,
    rules,
  })
  return {
    id: data.id,
    name: input.name,
    description: input.description,
    enabled: input.enabled,
    severity_threshold: input.severity_threshold,
    risk_score_threshold: input.risk_score_threshold,
    sla_hours: input.sla_hours,
  }
}

export async function updatePolicy(id: string, input: PolicyInput): Promise<Policy> {
  const rules = buildPolicyRules(input)

  await api.put(`/api/v1/policies/${id}`, {
    name: input.name,
    description: input.description ?? '',
    is_enabled: input.enabled,
    rules,
  })
  return {
    id,
    name: input.name,
    description: input.description,
    enabled: input.enabled,
    severity_threshold: input.severity_threshold,
    risk_score_threshold: input.risk_score_threshold,
    sla_hours: input.sla_hours,
  }
}

export async function deletePolicy(id: string): Promise<void> {
  await api.delete(`/api/v1/policies/${id}`)
}
