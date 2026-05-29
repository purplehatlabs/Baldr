import type { Severity } from './findings'
import { api } from './client'

export type SupplyChainSignalType =
  | 'malicious_package'
  | 'typosquat'
  | 'dependency_confusion'
  | 'suspicious_behavior'

export type SupplyChainSignalStatus = 'open' | 'triaged' | 'suppressed' | 'resolved'

export interface SupplyChainSignal {
  id: string
  repo_id?: string | null
  repo_full_name?: string | null
  package_ecosystem: string
  package_name: string
  package_version: string
  signal_type: SupplyChainSignalType | string
  status: SupplyChainSignalStatus | string
  severity: Severity
  source_engine: string
  signal_key: string
  signal_hash?: string
  confidence?: number | null
  reasoning?: string
  evidence?: unknown
  metadata?: unknown
  evidence_json?: unknown
  metadata_json?: unknown
  first_seen_at?: string | null
  last_seen_at?: string | null
  created_at?: string
  updated_at?: string
}

export interface ListSupplyChainSignalsParams {
  status?: SupplyChainSignalStatus | string
  engine?: string
  signal_type?: SupplyChainSignalType | string
  severity?: Severity
  repo_id?: string
  q?: string
  page?: number
  per_page?: number
}

export interface SupplyChainSignalsPage {
  items: SupplyChainSignal[]
  total: number
  page: number
  per_page: number
  total_pages: number
}

export interface SupplyChainSignalsSummary {
  total: number
  by_status: Record<string, number>
  by_severity: Record<string, number>
  by_engine: Record<string, number>
  by_signal_type: Record<string, number>
}

function asRecord(value: unknown): Record<string, unknown> | null {
  if (!value || typeof value !== 'object') return null
  return value as Record<string, unknown>
}

function asNumber(value: unknown, fallback: number): number {
  return typeof value === 'number' && Number.isFinite(value) ? value : fallback
}

function asSignalsArray(value: unknown): SupplyChainSignal[] {
  if (!Array.isArray(value)) return []
  return (value as SupplyChainSignal[]).map((signal) => ({
    ...signal,
    signal_key: signal.signal_key || signal.signal_hash || '',
  }))
}

function asNumericMap(value: unknown): Record<string, number> {
  const record = asRecord(value)
  if (!record) return {}

  return Object.entries(record).reduce<Record<string, number>>((acc, [key, mapValue]) => {
    if (typeof mapValue === 'number' && Number.isFinite(mapValue)) {
      acc[key] = mapValue
    }
    return acc
  }, {})
}

function normalizeSupplyChainSignalsPage(data: unknown): SupplyChainSignalsPage {
  if (Array.isArray(data)) {
    return {
      items: data as SupplyChainSignal[],
      total: data.length,
      page: 1,
      per_page: data.length || 20,
      total_pages: 1,
    }
  }

  const record = asRecord(data)
  if (!record) {
    return {
      items: [],
      total: 0,
      page: 1,
      per_page: 20,
      total_pages: 0,
    }
  }

  const items = asSignalsArray(record.items ?? record.signals ?? record.results ?? record.data)
  const total = asNumber(record.total, items.length)
  const page = asNumber(record.page, 1)
  const pageSize = asNumber(record.page_size ?? record.per_page, items.length || 20)
  const totalPages = asNumber(record.total_pages, pageSize > 0 ? Math.ceil(total / pageSize) : 0)

  return {
    items,
    total,
    page,
    per_page: pageSize,
    total_pages: totalPages,
  }
}

function normalizeSummary(data: unknown): SupplyChainSignalsSummary {
  const record = asRecord(data)
  if (!record) {
    return {
      total: 0,
      by_status: {},
      by_severity: {},
      by_engine: {},
      by_signal_type: {},
    }
  }

  const byStatus = asNumericMap(record.by_status ?? record.statuses)
  const bySeverity = asNumericMap(record.by_severity ?? record.severities)
  const byEngine = asNumericMap(record.by_engine ?? record.engines)
  const bySignalType = asNumericMap(record.by_signal_type ?? record.signal_types)

  const totalFromMaps =
    Object.values(byStatus).reduce((acc, value) => acc + value, 0) ||
    Object.values(bySignalType).reduce((acc, value) => acc + value, 0)

  return {
    total: asNumber(record.total, totalFromMaps),
    by_status: byStatus,
    by_severity: bySeverity,
    by_engine: byEngine,
    by_signal_type: bySignalType,
  }
}

export async function listSupplyChainSignals(
  params?: ListSupplyChainSignalsParams,
): Promise<SupplyChainSignalsPage> {
  const { data } = await api.get('/api/v1/supply-chain-signals', { params })
  return normalizeSupplyChainSignalsPage(data)
}

export async function getSupplyChainSignalsSummary(
  params?: Omit<ListSupplyChainSignalsParams, 'page' | 'page_size'>,
): Promise<SupplyChainSignalsSummary> {
  const { data } = await api.get('/api/v1/supply-chain-signals/summary', { params })
  return normalizeSummary(data)
}

export async function getSupplyChainSignalById(id: string): Promise<SupplyChainSignal> {
  const { data } = await api.get<SupplyChainSignal>(`/api/v1/supply-chain-signals/${id}`)
  return {
    ...data,
    signal_key: data.signal_key || data.signal_hash || '',
    evidence_json: data.evidence_json ?? data.evidence,
    metadata_json: data.metadata_json ?? data.metadata,
  }
}
