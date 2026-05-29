import { api } from './client'

export type SavedViewScope = 'findings'

export interface SavedViewFilters {
  q?: string
  severity?: string
  status?: string
  team_id?: string
  repo_id?: string
  reachability?: string
  risk_tier?: string
  sla_breached?: boolean
  triage_queue?: 'pending'
  triage_status?: string
  source_engine?: string
  sort?: string
  order?: 'asc' | 'desc'
  page_size?: number
}

export interface SavedView {
  id: string
  name: string
  scope: SavedViewScope
  filters: SavedViewFilters
  sort?: string
  order?: 'asc' | 'desc'
  page_size?: number
  created_at?: string
  updated_at?: string
}

export interface SavedViewInput {
  name: string
  scope: SavedViewScope
  filters: SavedViewFilters
}

function asRecord(value: unknown): Record<string, unknown> | null {
  if (!value || typeof value !== 'object') return null
  return value as Record<string, unknown>
}

function asViewsArray(value: unknown): SavedView[] {
  if (!Array.isArray(value)) return []
  return value.map((item) => {
    const record = asRecord(item) ?? {}
    const id = typeof record.id === 'string' ? record.id : ''
    const name = typeof record.name === 'string' ? record.name : 'Saved view'
    return {
      id,
      name,
      scope: 'findings',
      filters: (record.filters as SavedViewFilters) ?? {},
      sort: typeof record.sort === 'string' ? record.sort : undefined,
      order: record.order === 'asc' ? 'asc' : record.order === 'desc' ? 'desc' : undefined,
      page_size: typeof record.page_size === 'number' ? record.page_size : undefined,
    }
  })
}

export async function listSavedViews(scope: SavedViewScope): Promise<SavedView[]> {
  const { data } = await api.get('/api/v1/views', { params: { scope } })
  if (Array.isArray(data)) return data as SavedView[]

  const record = asRecord(data)
  return asViewsArray(record?.items ?? record?.views ?? record?.results)
}

export async function createSavedView(input: SavedViewInput): Promise<SavedView> {
  const { data } = await api.post<{ id: string }>('/api/v1/views', {
    name: input.name,
    filters: input.filters,
    sort: input.filters.sort ?? 'last_seen_at',
    order: input.filters.order ?? 'desc',
    page_size: input.filters.page_size ?? 20,
  })
  return {
    id: data.id,
    name: input.name,
    scope: 'findings',
    filters: input.filters,
    sort: input.filters.sort,
    order: input.filters.order,
    page_size: input.filters.page_size,
  }
}

export async function updateSavedView(id: string, input: SavedViewInput): Promise<SavedView> {
  await api.put(`/api/v1/views/${id}`, {
    name: input.name,
    filters: input.filters,
    sort: input.filters.sort ?? 'last_seen_at',
    order: input.filters.order ?? 'desc',
    page_size: input.filters.page_size ?? 20,
  })
  return {
    id,
    name: input.name,
    scope: 'findings',
    filters: input.filters,
    sort: input.filters.sort,
    order: input.filters.order,
    page_size: input.filters.page_size,
  }
}

export async function deleteSavedView(id: string): Promise<void> {
  await api.delete(`/api/v1/views/${id}`)
}
