import { useEffect, useMemo, useState } from 'react'
import { useLocation, useSearchParams } from 'react-router-dom'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useTranslation } from 'react-i18next'
import {
  Bug,
  ChevronDown,
  ChevronLeft,
  ChevronRight,
  ChevronUp,
  ExternalLink,
  GitBranch,
  RefreshCw,
  Search,
  Sparkles,
  X,
} from 'lucide-react'
import {
  analyzeFinding,
  confirmFindingTriage,
  dismissFindingTriage,
  bulkUpdateFindings,
  getFinding,
  listFindings,
  reopenFindingTriage,
  updateFindingStatus,
  type AnalysisStatus,
  type CriticalityVerdict,
  type ExploitabilityVerdict,
  type Finding,
  type FindingBulkAction,
  type FindingSortField,
  type FindingStatus,
  type ReachabilityStatus,
  type RiskTier,
  type Severity,
  type SortOrder,
  type SourceEngine,
  type TriageStatus,
} from '@/api/findings'
import { useAuth } from '@/hooks/useAuth'
import { listRepos } from '@/api/repos'
import { listTeams } from '@/api/teams'
import {
  createSavedView,
  deleteSavedView,
  listSavedViews,
  updateSavedView,
  type SavedView,
  type SavedViewFilters,
} from '@/api/views'
import { EmptyState } from '@/components/shared/EmptyState'
import { SeverityBadge } from '@/components/shared/SeverityBadge'
import { StatusBadge } from '@/components/shared/StatusBadge'
import { PageSpinner } from '@/components/shared/Spinner'
import { cn, meetsMinSeverity } from '@/lib/utils'
import { getLLMStatus } from '@/api/settings'
import { getAppLocale } from '@/i18n'
import { formatDateTime } from '@/lib/locale'

function useFindingFilterOptions() {
  const { t } = useTranslation()

  return useMemo(
    () => ({
      severities: [
        { value: '' as Severity | '', label: t('findings.filters.allSeverities') },
        { value: 'critical' as const, label: t('findings.severity.critical') },
        { value: 'high' as const, label: t('findings.severity.high') },
        { value: 'medium' as const, label: t('findings.severity.medium') },
        { value: 'low' as const, label: t('findings.severity.low') },
        { value: 'unknown' as const, label: t('findings.severity.unknown') },
      ],
      statuses: [
        { value: '' as FindingStatus | '', label: t('findings.filters.allStatuses') },
        { value: 'open' as const, label: t('findings.status.open') },
        { value: 'suppressed' as const, label: t('findings.status.suppressed') },
        { value: 'fixed' as const, label: t('findings.status.fixed') },
      ],
      triageStatusOptions: [
        { value: 'pending' as const, label: t('findings.filters.pendingTriage') },
        { value: 'new' as const, label: t('findings.triage.new') },
        { value: 'needs_review' as const, label: t('findings.triage.needsReview') },
        { value: 'confirmed' as const, label: t('findings.triage.confirmed') },
        { value: 'dismissed' as const, label: t('findings.triage.dismissed') },
        { value: '' as TriageStatus | '' | 'pending', label: t('findings.filters.allTriage') },
      ],
      bulkActions: [
        { value: 'suppress' as const, label: t('findings.bulk.suppress') },
        { value: 'reopen' as const, label: t('findings.bulk.reopen') },
        { value: 'mark_fixed' as const, label: t('findings.bulk.markFixed') },
        { value: 'assign' as const, label: t('findings.bulk.assign') },
      ],
      sortOptions: [
        { value: 'risk_score' as const, label: t('findings.sort.riskScore') },
        { value: 'last_seen_at' as const, label: t('findings.sort.lastSeen') },
        { value: 'first_seen_at' as const, label: t('findings.sort.firstSeen') },
        { value: 'severity' as const, label: t('findings.sort.severity') },
        { value: 'status' as const, label: t('findings.sort.status') },
        { value: 'cvss_score' as const, label: t('findings.sort.cvss') },
        { value: 'package_name' as const, label: t('findings.sort.package') },
      ],
      reachabilityOptions: [
        { value: '' as ReachabilityStatus | '', label: t('findings.reachability.all') },
        { value: 'reachable' as const, label: t('findings.reachability.reachable') },
        { value: 'unreachable' as const, label: t('findings.reachability.unreachable') },
        { value: 'unknown' as const, label: t('findings.reachability.unknown') },
      ],
      riskTierOptions: [
        { value: '' as RiskTier | '', label: t('findings.riskTier.all') },
        { value: 'critical' as const, label: t('findings.riskTier.critical') },
        { value: 'high' as const, label: t('findings.riskTier.high') },
        { value: 'medium' as const, label: t('findings.riskTier.medium') },
        { value: 'low' as const, label: t('findings.riskTier.low') },
      ],
      sourceEngineOptions: [
        { value: '' as SourceEngine | '', label: t('findings.source.all') },
        { value: 'osv' as const, label: t('findings.source.osv') },
        { value: 'manual' as const, label: t('findings.source.manual') },
        { value: 'dataset' as const, label: t('findings.source.dataset') },
        { value: 'guarddog' as const, label: t('findings.source.guarddog') },
        { value: 'openssf_pa' as const, label: t('findings.source.openssf_pa') },
      ],
    }),
    [t],
  )
}

export default function FindingsPage() {
  const { t } = useTranslation()
  const {
    severities,
    statuses,
    triageStatusOptions,
    bulkActions,
    sortOptions,
    reachabilityOptions,
    riskTierOptions,
    sourceEngineOptions,
  } = useFindingFilterOptions()
  const location = useLocation()
  const isTriagePage = location.pathname === '/triage'
  const [searchParams, setSearchParams] = useSearchParams()
  const queryClient = useQueryClient()
  const repoId = searchParams.get('repo_id') ?? ''
  const repoName = searchParams.get('repo_name') ?? ''

  const [severity, setSeverity] = useState<Severity | ''>('')
  const [status, setStatus] = useState<FindingStatus | ''>('open')
  const [teamId, setTeamId] = useState('')
  const [qInput, setQInput] = useState('')
  const [q, setQ] = useState('')
  const [sort, setSort] = useState<FindingSortField>('risk_score')
  const [order, setOrder] = useState<SortOrder>('desc')
  const [reachability, setReachability] = useState<ReachabilityStatus | ''>('')
  const [riskTier, setRiskTier] = useState<RiskTier | ''>('')
  const [slaBreachedOnly, setSlaBreachedOnly] = useState(false)
  const [triageFilter, setTriageFilter] = useState<TriageStatus | '' | 'pending'>(isTriagePage ? 'pending' : '')
  const [sourceEngine, setSourceEngine] = useState<SourceEngine | ''>('')
  const [page, setPage] = useState(1)
  const [pageSize, setPageSize] = useState(20)
  const [selectedId, setSelectedId] = useState<string | null>(null)
  const [selectedIds, setSelectedIds] = useState<Set<string>>(new Set())
  const [bulkAction, setBulkAction] = useState<FindingBulkAction>('suppress')
  const [assignTarget, setAssignTarget] = useState('')
  const [newViewName, setNewViewName] = useState('')
  const [activeViewId, setActiveViewId] = useState('')

  const { data: teams = [] } = useQuery({
    queryKey: ['teams'],
    queryFn: listTeams,
  })

  const { data: repos = [] } = useQuery({
    queryKey: ['repos'],
    queryFn: () => listRepos(),
  })

  const sortedRepos = useMemo(
    () => [...repos].sort((a, b) => a.full_name.localeCompare(b.full_name)),
    [repos],
  )

  const { data: views = [] } = useQuery({
    queryKey: ['saved-views', 'findings'],
    queryFn: () => listSavedViews('findings'),
  })

  const {
    data: findingsPage,
    isLoading,
    isFetching,
    refetch,
  } = useQuery({
    queryKey: [
      'findings',
      severity,
      status,
      teamId,
      repoId,
      q,
      reachability,
      riskTier,
      slaBreachedOnly,
      triageFilter,
      sourceEngine,
      page,
      pageSize,
      sort,
      order,
    ],
    queryFn: () =>
      listFindings({
        severity: severity || undefined,
        status: status || undefined,
        team_id: teamId || undefined,
        repo_id: repoId || undefined,
        q: q || undefined,
        reachability: reachability || undefined,
        risk_tier: riskTier || undefined,
        sla_breached: slaBreachedOnly || undefined,
        triage_queue: triageFilter === 'pending' ? 'pending' : undefined,
        triage_status: triageFilter && triageFilter !== 'pending' ? triageFilter : undefined,
        source_engine: sourceEngine || undefined,
        page,
        page_size: pageSize,
        sort,
        order,
      }),
  })

  const updateMutation = useMutation({
    mutationFn: ({ id, newStatus }: { id: string; newStatus: FindingStatus }) =>
      updateFindingStatus(id, newStatus),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['findings'] })
      queryClient.invalidateQueries({ queryKey: ['dashboard'] })
      setSelectedId(null)
    },
  })

  const bulkMutation = useMutation({
    mutationFn: bulkUpdateFindings,
    onSuccess: () => {
      setSelectedIds(new Set())
      queryClient.invalidateQueries({ queryKey: ['findings'] })
      queryClient.invalidateQueries({ queryKey: ['dashboard'] })
    },
  })

  const createViewMutation = useMutation({
    mutationFn: createSavedView,
    onSuccess: (view) => {
      setActiveViewId(view.id)
      setNewViewName('')
      queryClient.invalidateQueries({ queryKey: ['saved-views', 'findings'] })
    },
  })

  const updateViewMutation = useMutation({
    mutationFn: ({ id, payload }: { id: string; payload: { name: string; scope: 'findings'; filters: SavedViewFilters } }) =>
      updateSavedView(id, payload),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['saved-views', 'findings'] })
    },
  })

  const deleteViewMutation = useMutation({
    mutationFn: deleteSavedView,
    onSuccess: () => {
      setActiveViewId('')
      queryClient.invalidateQueries({ queryKey: ['saved-views', 'findings'] })
    },
  })

  const items = findingsPage?.items ?? []
  const total = findingsPage?.total ?? 0
  const totalPages = findingsPage?.total_pages ?? 0

  const allSelected = items.length > 0 && items.every((item) => selectedIds.has(item.id))
  const selectedCount = selectedIds.size

  const selectedView = useMemo(
    () => views.find((view) => view.id === activeViewId) ?? null,
    [views, activeViewId],
  )

  useEffect(() => {
    setSelectedIds(new Set())
  }, [page, pageSize, severity, status, teamId, repoId, q, sort, order, reachability, riskTier, slaBreachedOnly, triageFilter, sourceEngine])

  const clearRepoFilter = () => {
    const next = new URLSearchParams(searchParams)
    next.delete('repo_id')
    next.delete('repo_name')
    setSearchParams(next, { replace: true })
    setPage(1)
  }

  const setRepoFilter = (nextRepoId: string) => {
    const next = new URLSearchParams(searchParams)
    if (nextRepoId) {
      const repo = sortedRepos.find((item) => item.id === nextRepoId)
      next.set('repo_id', nextRepoId)
      if (repo) next.set('repo_name', repo.full_name)
      else next.delete('repo_name')
    } else {
      next.delete('repo_id')
      next.delete('repo_name')
    }
    setSearchParams(next, { replace: true })
    setPage(1)
  }

  const handleColumnSort = (field: FindingSortField) => {
    setPage(1)
    if (sort === field) {
      setOrder((current) => (current === 'asc' ? 'desc' : 'asc'))
      return
    }
    setSort(field)
    setOrder('desc')
  }

  const applySearch = () => {
    setPage(1)
    setQ(qInput.trim())
  }

  const toggleSortOrder = () => {
    setPage(1)
    setOrder((current) => (current === 'asc' ? 'desc' : 'asc'))
  }

  const toggleAll = () => {
    const next = new Set(selectedIds)
    if (allSelected) {
      items.forEach((item) => next.delete(item.id))
    } else {
      items.forEach((item) => next.add(item.id))
    }
    setSelectedIds(next)
  }

  const toggleOne = (id: string) => {
    const next = new Set(selectedIds)
    if (next.has(id)) next.delete(id)
    else next.add(id)
    setSelectedIds(next)
  }

  const runBulkAction = () => {
    const ids = Array.from(selectedIds)
    if (ids.length === 0) return

    const payload: {
      ids: string[]
      action: FindingBulkAction
      assignee_user_id?: string
    } = {
      ids,
      action: bulkAction,
    }

    if (bulkAction === 'assign') {
      const normalizedTarget = assignTarget.trim()
      if (!normalizedTarget) return
      payload.assignee_user_id = normalizedTarget
    }

    bulkMutation.mutate(payload)
  }

  const serializeCurrentFilters = (): SavedViewFilters => ({
    q: q || undefined,
    severity: severity || undefined,
    status: status || undefined,
    team_id: teamId || undefined,
    repo_id: repoId || undefined,
    reachability: reachability || undefined,
    risk_tier: riskTier || undefined,
    sla_breached: slaBreachedOnly || undefined,
    triage_queue: triageFilter === 'pending' ? 'pending' : undefined,
    triage_status: triageFilter && triageFilter !== 'pending' ? triageFilter : undefined,
    source_engine: sourceEngine || undefined,
    sort,
    order,
    page_size: pageSize,
  })

  const applySavedView = (view: SavedView | null) => {
    if (!view) return
    const filters = view.filters ?? {}

    setSeverity(asSeverity(filters.severity))
    setStatus(asStatus(filters.status))
    setTeamId(asString(filters.team_id))
    setQ(asString(filters.q))
    setQInput(asString(filters.q))
    setSort(asSortField(filters.sort))
    setOrder(asSortOrder(filters.order))
    setPageSize(asPageSize(filters.page_size))
    setReachability(asReachability(filters.reachability))
    setRiskTier(asRiskTier(filters.risk_tier))
    setSlaBreachedOnly(filters.sla_breached === true)
    if (filters.triage_queue === 'pending') {
      setTriageFilter('pending')
    } else if (filters.triage_status) {
      setTriageFilter(asTriageStatus(filters.triage_status))
    } else {
      setTriageFilter(isTriagePage ? 'pending' : '')
    }
    setSourceEngine(asSourceEngine(filters.source_engine))
    setPage(1)

    if (filters.repo_id) {
      const next = new URLSearchParams(searchParams)
      next.set('repo_id', String(filters.repo_id))
      const matchedRepo = sortedRepos.find((item) => item.id === String(filters.repo_id))
      if (matchedRepo) next.set('repo_name', matchedRepo.full_name)
      else next.delete('repo_name')
      setSearchParams(next, { replace: true })
    } else {
      const next = new URLSearchParams(searchParams)
      next.delete('repo_id')
      next.delete('repo_name')
      setSearchParams(next, { replace: true })
    }
  }

  if (isLoading) return <PageSpinner />

  const from = total === 0 ? 0 : (page - 1) * pageSize + 1
  const to = total === 0 ? 0 : Math.min(page * pageSize, total)

  return (
    <div className="space-y-4">
      {repoId && (
        <div className="inline-flex items-center gap-2 rounded-lg bg-brand-50 text-brand-700 ring-1 ring-brand-100 px-3 py-1.5 text-sm">
          <GitBranch className="w-4 h-4" />
          <span className="font-medium">{t('findings.repoFilter')}</span>
          <span className="font-mono">{repoName || repoId}</span>
          <button
            onClick={clearRepoFilter}
            className="ml-1 text-brand-600 hover:text-brand-800"
            title={t('findings.clearRepoFilter')}
          >
            <X className="w-3.5 h-3.5" />
          </button>
        </div>
      )}

      <div className="bg-white rounded-xl border border-gray-200 p-4 space-y-3">
        <div className="flex flex-wrap items-center gap-3">
          <div className="relative min-w-[240px] flex-1">
            <Search className="w-4 h-4 text-gray-400 absolute left-3 top-1/2 -translate-y-1/2" />
            <input
              value={qInput}
              onChange={(event) => setQInput(event.target.value)}
              onKeyDown={(event) => {
                if (event.key === 'Enter') applySearch()
              }}
              placeholder={t('findings.searchPlaceholder')}
              className="w-full text-sm border border-gray-200 rounded-lg pl-9 pr-3 py-2 bg-white focus:outline-none focus:ring-2 focus:ring-brand-500"
            />
          </div>
          <button
            onClick={applySearch}
            className="inline-flex items-center gap-1.5 text-sm border border-gray-200 rounded-lg px-3 py-2 bg-white hover:bg-gray-50"
          >
            {t('common.search')}
          </button>
          {q && (
            <button
              onClick={() => {
                setQ('')
                setQInput('')
                setPage(1)
              }}
              className="inline-flex items-center gap-1 text-sm text-gray-500 hover:text-gray-700"
            >
              <X className="w-3.5 h-3.5" />
              {t('common.clearSearch')}
            </button>
          )}
        </div>

        <div className="flex flex-wrap gap-3">
          <select
            value={severity}
            onChange={(event) => {
              setSeverity(event.target.value as Severity | '')
              setPage(1)
            }}
            className="text-sm border border-gray-200 rounded-lg px-3 py-1.5 bg-white focus:outline-none focus:ring-2 focus:ring-brand-500"
          >
            {severities.map((item) => (
              <option key={item.value} value={item.value}>
                {item.label}
              </option>
            ))}
          </select>

          <select
            value={status}
            onChange={(event) => {
              setStatus(event.target.value as FindingStatus | '')
              setPage(1)
            }}
            className="text-sm border border-gray-200 rounded-lg px-3 py-1.5 bg-white focus:outline-none focus:ring-2 focus:ring-brand-500"
          >
            {statuses.map((item) => (
              <option key={item.value} value={item.value}>
                {item.label}
              </option>
            ))}
          </select>

          {teams.length > 0 && (
            <select
              value={teamId}
              onChange={(event) => {
                setTeamId(event.target.value)
                setPage(1)
              }}
              className="text-sm border border-gray-200 rounded-lg px-3 py-1.5 bg-white focus:outline-none focus:ring-2 focus:ring-brand-500"
            >
              <option value="">{t('findings.filters.allTeams')}</option>
              {teams.map((team) => (
                <option key={team.id} value={team.id}>
                  {team.display_name}
                </option>
              ))}
            </select>
          )}

          {sortedRepos.length > 0 && (
            <select
              value={repoId}
              onChange={(event) => setRepoFilter(event.target.value)}
              className="text-sm border border-gray-200 rounded-lg px-3 py-1.5 bg-white focus:outline-none focus:ring-2 focus:ring-brand-500 min-w-[220px]"
            >
              <option value="">{t('findings.filters.allRepos')}</option>
              {sortedRepos.map((repo) => (
                <option key={repo.id} value={repo.id}>
                  {repo.full_name}
                </option>
              ))}
            </select>
          )}

          <select
            value={reachability}
            onChange={(event) => {
              setReachability(event.target.value as ReachabilityStatus | '')
              setPage(1)
            }}
            className="text-sm border border-gray-200 rounded-lg px-3 py-1.5 bg-white focus:outline-none focus:ring-2 focus:ring-brand-500"
          >
            {reachabilityOptions.map((item) => (
              <option key={item.value || 'all'} value={item.value}>
                {item.label}
              </option>
            ))}
          </select>

          <select
            value={riskTier}
            onChange={(event) => {
              setRiskTier(event.target.value as RiskTier | '')
              setPage(1)
            }}
            className="text-sm border border-gray-200 rounded-lg px-3 py-1.5 bg-white focus:outline-none focus:ring-2 focus:ring-brand-500"
          >
            {riskTierOptions.map((item) => (
              <option key={item.value || 'all'} value={item.value}>
                {item.label}
              </option>
            ))}
          </select>

          <select
            value={sourceEngine}
            onChange={(event) => {
              setSourceEngine(event.target.value as SourceEngine | '')
              setPage(1)
            }}
            className="text-sm border border-gray-200 rounded-lg px-3 py-1.5 bg-white focus:outline-none focus:ring-2 focus:ring-brand-500"
          >
            {sourceEngineOptions.map((item) => (
              <option key={item.value || 'all'} value={item.value}>
                {item.label}
              </option>
            ))}
          </select>

          <select
            value={triageFilter}
            onChange={(event) => {
              setTriageFilter(event.target.value as TriageStatus | '' | 'pending')
              setPage(1)
            }}
            className="text-sm border border-gray-200 rounded-lg px-3 py-1.5 bg-white focus:outline-none focus:ring-2 focus:ring-brand-500"
          >
            {triageStatusOptions.map((item) => (
              <option key={item.value || 'all'} value={item.value}>
                {item.label}
              </option>
            ))}
          </select>

          <label className="inline-flex items-center gap-2 text-sm text-gray-700">
            <input
              type="checkbox"
              checked={slaBreachedOnly}
              onChange={(event) => {
                setSlaBreachedOnly(event.target.checked)
                setPage(1)
              }}
              className="h-4 w-4 rounded border-gray-300 text-brand-600 focus:ring-brand-500"
            />
            {t('findings.filters.slaBreach')}
          </label>

          <select
            value={sort}
            onChange={(event) => {
              setSort(event.target.value as FindingSortField)
              setPage(1)
            }}
            className="text-sm border border-gray-200 rounded-lg px-3 py-1.5 bg-white focus:outline-none focus:ring-2 focus:ring-brand-500"
          >
            {sortOptions.map((option) => (
              <option key={option.value} value={option.value}>
                {option.label}
              </option>
            ))}
          </select>

          <button
            onClick={toggleSortOrder}
            className="inline-flex items-center gap-1.5 text-sm border border-gray-200 rounded-lg px-3 py-1.5 bg-white hover:bg-gray-50"
          >
            {t('findings.sortOrder', { order: order === 'desc' ? t('findings.sortDesc') : t('findings.sortAsc') })}
          </button>

          <button
            onClick={() => refetch()}
            disabled={isFetching}
            className="inline-flex items-center gap-1.5 text-sm border border-gray-200 rounded-lg px-3 py-1.5 bg-white hover:bg-gray-50 disabled:opacity-50"
          >
            <RefreshCw className={cn('w-3.5 h-3.5', isFetching && 'animate-spin')} />
            {t('common.refresh')}
          </button>

          <span className="ml-auto text-sm text-gray-500 self-center">
            {t('findings.count', { count: total })}
          </span>
        </div>

        <div className="flex flex-wrap items-center gap-2">
          <select
            value={activeViewId}
            onChange={(event) => {
              const value = event.target.value
              setActiveViewId(value)
              const view = views.find((item) => item.id === value) ?? null
              applySavedView(view)
            }}
            className="text-sm border border-gray-200 rounded-lg px-3 py-1.5 bg-white focus:outline-none focus:ring-2 focus:ring-brand-500 min-w-[220px]"
          >
            <option value="">{t('findings.savedViews')}</option>
            {views.map((view) => (
              <option key={view.id} value={view.id}>
                {view.name}
              </option>
            ))}
          </select>
          <input
            value={newViewName}
            onChange={(event) => setNewViewName(event.target.value)}
            placeholder={t('findings.viewNamePlaceholder')}
            className="text-sm border border-gray-200 rounded-lg px-3 py-1.5 bg-white focus:outline-none focus:ring-2 focus:ring-brand-500 min-w-[220px]"
          />
          <button
            onClick={() =>
              createViewMutation.mutate({
                name: newViewName.trim(),
                scope: 'findings',
                filters: serializeCurrentFilters(),
              })
            }
            disabled={createViewMutation.isPending || !newViewName.trim()}
            className="text-sm px-3 py-1.5 rounded-lg bg-brand-600 text-white hover:bg-brand-700 disabled:opacity-50"
          >
            {t('findings.saveNewView')}
          </button>
          <button
            onClick={() => {
              if (!selectedView) return
              updateViewMutation.mutate({
                id: selectedView.id,
                payload: {
                  name: selectedView.name,
                  scope: 'findings',
                  filters: serializeCurrentFilters(),
                },
              })
            }}
            disabled={updateViewMutation.isPending || !selectedView}
            className="text-sm px-3 py-1.5 rounded-lg border border-gray-200 hover:bg-gray-50 disabled:opacity-50"
          >
            {t('common.refresh')} view
          </button>
          <button
            onClick={() => {
              if (!selectedView) return
              deleteViewMutation.mutate(selectedView.id)
            }}
            disabled={deleteViewMutation.isPending || !selectedView}
            className="text-sm px-3 py-1.5 rounded-lg border border-red-200 text-red-600 hover:bg-red-50 disabled:opacity-50"
          >
            {t('findings.removeView')}
          </button>
        </div>
      </div>

      {selectedCount > 0 && (
        <div className="bg-brand-50 border border-brand-100 rounded-xl p-3 flex flex-wrap items-center gap-2">
          <span className="text-sm text-brand-800 font-medium">
            {t('common.selected', { count: selectedCount })}
          </span>
          <select
            value={bulkAction}
            onChange={(event) => setBulkAction(event.target.value as FindingBulkAction)}
            className="text-sm border border-brand-200 rounded-lg px-3 py-1.5 bg-white"
          >
            {bulkActions.map((action) => (
              <option key={action.value} value={action.value}>
                {action.label}
              </option>
            ))}
          </select>
          {bulkAction === 'assign' && (
            <input
              value={assignTarget}
              onChange={(event) => setAssignTarget(event.target.value)}
              placeholder={t('findings.bulk.assignPlaceholder')}
              title={t('findings.bulk.assignTitle')}
              className="text-sm border border-brand-200 rounded-lg px-3 py-1.5 bg-white min-w-[220px]"
            />
          )}
          <button
            onClick={runBulkAction}
            disabled={bulkMutation.isPending || (bulkAction === 'assign' && !assignTarget.trim())}
            className="text-sm px-3 py-1.5 rounded-lg bg-brand-700 text-white hover:bg-brand-800 disabled:opacity-50"
          >
            {bulkMutation.isPending ? t('findings.bulk.applying') : t('findings.bulk.apply')}
          </button>
          <button
            onClick={() => setSelectedIds(new Set())}
            className="text-sm px-3 py-1.5 rounded-lg border border-brand-200 text-brand-700 hover:bg-white"
          >
            {t('findings.bulk.clearSelection')}
          </button>
        </div>
      )}

      {items.length === 0 ? (
        <div className="bg-white rounded-xl border border-gray-200">
          <EmptyState
            icon={Bug}
            title={t('findings.emptyTitle')}
            description={t('findings.emptyDescription')}
          />
        </div>
      ) : (
        <div className="bg-white rounded-xl border border-gray-200 overflow-hidden">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-gray-100 bg-gray-50">
                <th className="px-4 py-3 w-8">
                  <input
                    type="checkbox"
                    checked={allSelected}
                    onChange={toggleAll}
                    className="h-4 w-4 rounded border-gray-300 text-brand-600 focus:ring-brand-500"
                  />
                </th>
                <SortableTableHeader
                  label={t('findings.columns.risk')}
                  field="risk_score"
                  currentSort={sort}
                  currentOrder={order}
                  onSort={handleColumnSort}
                />
                <SortableTableHeader
                  label={t('findings.columns.severity')}
                  field="severity"
                  currentSort={sort}
                  currentOrder={order}
                  onSort={handleColumnSort}
                />
                <SortableTableHeader
                  label={t('findings.columns.package')}
                  field="package_name"
                  currentSort={sort}
                  currentOrder={order}
                  onSort={handleColumnSort}
                />
                <th className="px-5 py-3 text-left font-medium text-gray-500">{t('findings.columns.source')}</th>
                <th className="px-5 py-3 text-left font-medium text-gray-500">{t('findings.columns.osvId')}</th>
                <th className="px-5 py-3 text-left font-medium text-gray-500">{t('findings.columns.repository')}</th>
                <th className="px-5 py-3 text-left font-medium text-gray-500">{t('findings.columns.manifest')}</th>
                <th className="px-5 py-3 text-left font-medium text-gray-500">{t('findings.columns.reachability')}</th>
                <th className="px-5 py-3 text-left font-medium text-gray-500">{t('findings.columns.triage')}</th>
                <th className="px-5 py-3 text-left font-medium text-gray-500">{t('findings.columns.exploitable')}</th>
                <SortableTableHeader
                  label={t('findings.columns.status')}
                  field="status"
                  currentSort={sort}
                  currentOrder={order}
                  onSort={handleColumnSort}
                />
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-50">
              {items.map((finding) => (
                <tr
                  key={finding.id}
                  className="hover:bg-gray-50 cursor-pointer transition-colors"
                  onClick={() => setSelectedId(finding.id)}
                >
                  <td className="px-4 py-3" onClick={(event) => event.stopPropagation()}>
                    <input
                      type="checkbox"
                      checked={selectedIds.has(finding.id)}
                      onChange={() => toggleOne(finding.id)}
                      className="h-4 w-4 rounded border-gray-300 text-brand-600 focus:ring-brand-500"
                    />
                  </td>
                  <td className="px-5 py-3">
                    <RiskScoreBadge
                      score={finding.risk_score}
                      tier={finding.risk_tier}
                      breached={finding.is_sla_breached}
                      partial={finding.risk_score != null && !finding.has_contextual_analysis}
                    />
                  </td>
                  <td className="px-5 py-3">
                    <SeverityBadge severity={finding.severity} />
                  </td>
                  <td className="px-5 py-3">
                    <span className="font-medium text-gray-900">{finding.package_name || '—'}</span>
                    {finding.package_version && (
                      <span className="text-gray-400 ml-1">@{finding.package_version}</span>
                    )}
                  </td>
                  <td className="px-5 py-3">
                    <SourceEngineBadge engine={finding.source_engine} />
                  </td>
                  <td className="px-5 py-3 font-mono text-xs text-gray-600">{finding.osv_id}</td>
                  <td className="px-5 py-3 text-gray-600 max-w-[180px] truncate">
                    {finding.repo_full_name || (finding.source_engine === 'manual' ? t('findings.tenantCatalog') : '—')}
                  </td>
                  <td className="px-5 py-3 font-mono text-xs text-gray-500 max-w-[160px] truncate">{finding.manifest_path}</td>
                  <td className="px-5 py-3">
                    <ReachabilityBadge status={finding.reachability_status} />
                  </td>
                  <td className="px-5 py-3">
                    <TriageBadge
                      status={finding.triage_status}
                      source={finding.triage_decision_source}
                    />
                  </td>
                  <td className="px-5 py-3">
                    <ExploitabilityBadge
                      verdict={finding.ai_exploitability_verdict}
                      status={finding.ai_analysis_status}
                    />
                  </td>
                  <td className="px-5 py-3">
                    <StatusBadge status={finding.status} />
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      <div className="flex flex-wrap items-center justify-between gap-3">
        <div className="text-sm text-gray-500">
          {t('common.showing', { from, to, total })}
        </div>
        <div className="flex items-center gap-2">
          <select
            value={pageSize}
            onChange={(event) => {
              setPageSize(Number(event.target.value))
              setPage(1)
            }}
            className="text-sm border border-gray-200 rounded-lg px-2 py-1.5 bg-white"
          >
            <option value={10}>{t('common.perPage', { count: 10 })}</option>
            <option value={20}>{t('common.perPage', { count: 20 })}</option>
            <option value={50}>{t('common.perPage', { count: 50 })}</option>
            <option value={100}>{t('common.perPage', { count: 100 })}</option>
          </select>
          <button
            onClick={() => setPage((current) => Math.max(1, current - 1))}
            disabled={page <= 1}
            className="inline-flex items-center gap-1.5 text-sm border border-gray-200 rounded-lg px-3 py-1.5 bg-white hover:bg-gray-50 disabled:opacity-50"
          >
            <ChevronLeft className="w-3.5 h-3.5" />
            {t('common.previous')}
          </button>
          <span className="text-sm text-gray-600">
            {totalPages > 0 ? t('common.pageOf', { page, total: totalPages }) : t('common.page', { page })}
          </span>
          <button
            onClick={() => setPage((current) => current + 1)}
            disabled={totalPages > 0 ? page >= totalPages : items.length < pageSize}
            className="inline-flex items-center gap-1.5 text-sm border border-gray-200 rounded-lg px-3 py-1.5 bg-white hover:bg-gray-50 disabled:opacity-50"
          >
            {t('common.next')}
            <ChevronRight className="w-3.5 h-3.5" />
          </button>
        </div>
      </div>

      {selectedId && (
        <FindingDetail
          findingId={selectedId}
          onClose={() => setSelectedId(null)}
          onUpdateStatus={(newStatus) => updateMutation.mutate({ id: selectedId, newStatus })}
          updating={updateMutation.isPending}
        />
      )}
    </div>
  )
}

function FindingDetail({
  findingId,
  onClose,
  onUpdateStatus,
  updating,
}: {
  findingId: string
  onClose: () => void
  onUpdateStatus: (status: FindingStatus) => void
  updating: boolean
}) {
  const { t } = useTranslation()
  const queryClient = useQueryClient()

  const { data: llmSettings } = useQuery({
    queryKey: ['settings', 'llm'],
    queryFn: getLLMStatus,
  })

  const { data: finding, isLoading } = useQuery({
    queryKey: ['finding', findingId],
    queryFn: () => getFinding(findingId),
    refetchInterval: (query) => {
      const analysisStatus = query.state.data?.ai_analysis_status
      if (analysisStatus === 'pending' || analysisStatus === 'running') return 3000
      return false
    },
  })

  const analyzeMutation = useMutation({
    mutationFn: () => analyzeFinding(findingId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['finding', findingId] })
      queryClient.invalidateQueries({ queryKey: ['findings'] })
    },
  })

  if (isLoading || !finding) {
    return (
      <div className="fixed inset-0 z-50 flex justify-end" onClick={onClose}>
        <div
          className="relative w-full max-w-lg bg-white shadow-xl h-full border-l border-gray-200 flex items-center justify-center"
          onClick={(event) => event.stopPropagation()}
        >
          <PageSpinner />
        </div>
      </div>
    )
  }

  return (
    <div className="fixed inset-0 z-50 flex justify-end" onClick={onClose}>
      <div
        className="relative w-full max-w-lg bg-white shadow-xl h-full overflow-y-auto border-l border-gray-200"
        onClick={(event) => event.stopPropagation()}
      >
        <div className="sticky top-0 bg-white border-b border-gray-100 px-6 py-4 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <SeverityBadge severity={finding.severity} />
            <span className="font-semibold text-gray-900 truncate">{finding.package_name}</span>
          </div>
          <button onClick={onClose} className="p-1 rounded-lg hover:bg-gray-100">
            <X className="w-5 h-5 text-gray-500" />
          </button>
        </div>

        <div className="p-6 space-y-6">
          <RiskScoreSection finding={finding} />

          <TriageSection findingId={findingId} finding={finding} onClose={onClose} />

          <AIAnalysisSection
            finding={finding}
            autoAnalysisMinSeverity={llmSettings?.auto_analysis_min_severity ?? 'high'}
            onAnalyze={() => analyzeMutation.mutate()}
            analyzing={analyzeMutation.isPending}
          />

          <div>
            <h3 className="text-xs font-semibold text-gray-500 uppercase tracking-wide mb-2">{t('findings.detail.summary')}</h3>
            <p className="text-sm text-gray-700">{finding.summary || t('findings.detail.noDescription')}</p>
          </div>

          <div className="grid grid-cols-2 gap-4">
            <InfoField label={t('findings.detail.source')} value={finding.source_engine ?? 'osv'} />
            <InfoField label={t('findings.detail.osvId')} value={finding.osv_id} mono />
            <InfoField label={t('findings.detail.cvss')} value={finding.cvss_score?.toFixed(1) ?? '—'} />
            <InfoField label={t('findings.detail.riskScore')} value={finding.risk_score != null ? `${finding.risk_score.toFixed(1)} (${finding.risk_tier ?? '—'})` : '—'} />
            <InfoField label={t('findings.detail.reachability')} value={finding.reachability_status ?? 'unknown'} />
            <InfoField label={t('findings.detail.slaDue')} value={finding.sla_due_at ? formatDateTime(finding.sla_due_at, getAppLocale()) : '—'} />
            <InfoField label="{t('findings.filters.slaBreach')}" value={finding.is_sla_breached ? t('common.yes') : t('common.no')} />
            <InfoField label={t('findings.detail.affectedVersion')} value={finding.package_version} mono />
            <InfoField
              label={t('findings.detail.fixedVersion')}
              value={finding.fixed_version ?? t('common.notAvailable')}
              mono={Boolean(finding.fixed_version)}
              highlight={Boolean(finding.fixed_version)}
            />
            <InfoField label={t('findings.detail.repository')} value={finding.repo_full_name || (finding.source_engine === 'manual' ? t('findings.tenantCatalog') : '—')} />
            <InfoField label={t('findings.detail.manifest')} value={finding.manifest_path || '—'} mono />
            {finding.external_source && (
              <InfoField label={t('findings.detail.externalSource')} value={finding.external_source} />
            )}
            {finding.business_impact && (
              <InfoField label={t('findings.detail.businessImpact')} value={finding.business_impact} />
            )}
          </div>

          {finding.risk_factors && finding.risk_factors.length > 0 && (
            <div>
              <h3 className="text-xs font-semibold text-gray-500 uppercase tracking-wide mb-2">
                {t('findings.detail.whyScore')}
              </h3>
              <ul className="space-y-1">
                {finding.risk_factors.map((factor) => (
                  <li key={`${factor.name}-${factor.detail ?? ''}`} className="text-sm text-gray-700">
                    {factor.name}: {factor.points > 0 ? '+' : ''}{factor.points.toFixed(1)}
                    {factor.detail ? ` (${factor.detail})` : ''}
                  </li>
                ))}
              </ul>
            </div>
          )}

          {finding.reachability_evidence && (
            <div>
              <h3 className="text-xs font-semibold text-gray-500 uppercase tracking-wide mb-2">{t('findings.detail.reachabilityEvidence')}</h3>
              <p className="text-sm text-gray-700">
                {finding.reachability_evidence.reason ??
                  (finding.reachability_evidence.matched_in?.length
                    ? t('findings.detail.matchedIn', { paths: finding.reachability_evidence.matched_in.join(', ') })
                    : t('findings.detail.noEvidence'))}
              </p>
            </div>
          )}

          <div>
            <h3 className="text-xs font-semibold text-gray-500 uppercase tracking-wide mb-2">
              {t('findings.detail.owners')}
            </h3>
            {finding.owners && finding.owners.length > 0 ? (
              <div className="flex flex-wrap gap-2">
                {finding.owners.map((owner, index) => (
                  <span
                    key={`${owner.github_login ?? owner.team_slug ?? owner.name}-${index}`}
                    className="inline-flex items-center gap-1.5 rounded-full bg-brand-50 text-brand-700 ring-1 ring-inset ring-brand-100 px-2.5 py-1 text-xs font-medium"
                    title={owner.email || owner.team_slug || undefined}
                  >
                    {owner.avatar_url ? (
                      <img src={owner.avatar_url} alt="" className="w-4 h-4 rounded-full" />
                    ) : null}
                    {owner.github_login ? `@${owner.github_login}` : owner.name}
                    {owner.team_slug && owner.source === 'team_fallback' ? (
                      <span className="text-brand-500/70">({owner.team_slug})</span>
                    ) : null}
                  </span>
                ))}
              </div>
            ) : finding.teams && finding.teams.length > 0 ? (
              <div className="flex flex-wrap gap-1.5">
                {finding.teams.map((team) => (
                  <span
                    key={team.id}
                    className="inline-flex items-center rounded-full bg-brand-50 text-brand-700 ring-1 ring-inset ring-brand-100 px-2.5 py-1 text-xs font-medium"
                  >
                    @{team.slug}
                  </span>
                ))}
              </div>
            ) : (
              <p className="text-sm text-gray-500">
                {t('findings.detail.noOwners')}
              </p>
            )}
          </div>

          <div>
            <h3 className="text-xs font-semibold text-gray-500 uppercase tracking-wide mb-2">
              {t('findings.detail.teamsCodeowners')}
            </h3>
            {finding.teams && finding.teams.length > 0 ? (
              <div className="flex flex-wrap gap-1.5">
                {finding.teams.map((team) => (
                  <span
                    key={team.id}
                    className="inline-flex items-center rounded-full bg-gray-100 text-gray-700 ring-1 ring-inset ring-gray-200 px-2.5 py-1 text-xs font-medium"
                  >
                    @{team.slug}
                  </span>
                ))}
              </div>
            ) : (
              <p className="text-sm text-gray-500">
                {t('findings.detail.noTeams', { manifest: finding.manifest_path })}{' '}
                <span className="font-mono">{finding.manifest_path}</span>.
              </p>
            )}
          </div>

          <div>
            <h3 className="text-xs font-semibold text-gray-500 uppercase tracking-wide mb-2">{t('findings.detail.status')}</h3>
            <div className="flex gap-2">
              {(['open', 'suppressed', 'fixed'] as FindingStatus[]).map((statusValue) => (
                <button
                  key={statusValue}
                  disabled={updating || finding.status === statusValue}
                  onClick={() => onUpdateStatus(statusValue)}
                  className={`px-3 py-1.5 rounded-lg text-xs font-medium transition-colors ${
                    finding.status === statusValue
                      ? 'bg-gray-900 text-white'
                      : 'bg-gray-100 text-gray-600 hover:bg-gray-200'
                  }`}
                >
                  {statusValue === 'open' ? t('findings.status.open') : statusValue === 'suppressed' ? t('findings.detail.suppress') : t('findings.status.fixed')}
                </button>
              ))}
            </div>
          </div>

          {finding.details && (
            <div>
              <h3 className="text-xs font-semibold text-gray-500 uppercase tracking-wide mb-2">{t('findings.detail.details')}</h3>
              <p className="text-sm text-gray-600 whitespace-pre-wrap">{finding.details}</p>
            </div>
          )}

          <a
            href={`https://osv.dev/vulnerability/${finding.osv_id}`}
            target="_blank"
            rel="noopener noreferrer"
            className="inline-flex items-center gap-1.5 text-sm text-brand-600 hover:underline"
          >
            {t('findings.detail.viewOsv')} <ExternalLink className="w-3.5 h-3.5" />
          </a>
        </div>
      </div>
    </div>
  )
}

function TriageSection({
  findingId,
  finding,
  onClose,
}: {
  findingId: string
  finding: Finding
  onClose: () => void
}) {
  const { t } = useTranslation()
  const queryClient = useQueryClient()
  const { user } = useAuth()
  const isAdmin = user?.role === 'admin' || user?.role === 'owner'
  const canDecide =
    finding.triage_status === 'new' || finding.triage_status === 'needs_review'

  const invalidate = () => {
    queryClient.invalidateQueries({ queryKey: ['finding', findingId] })
    queryClient.invalidateQueries({ queryKey: ['findings'] })
    queryClient.invalidateQueries({ queryKey: ['dashboard'] })
  }

  const confirmMutation = useMutation({
    mutationFn: () => confirmFindingTriage(findingId),
    onSuccess: () => {
      invalidate()
      onClose()
    },
  })

  const dismissMutation = useMutation({
    mutationFn: () => dismissFindingTriage(findingId),
    onSuccess: () => {
      invalidate()
      onClose()
    },
  })

  const reopenMutation = useMutation({
    mutationFn: () => reopenFindingTriage(findingId),
    onSuccess: invalidate,
  })

  const triageBusy =
    confirmMutation.isPending || dismissMutation.isPending || reopenMutation.isPending

  return (
    <div className="rounded-xl border border-gray-200 p-4 space-y-3">
      <div className="flex items-center justify-between gap-3">
        <div>
          <h3 className="text-xs font-semibold text-gray-500 uppercase tracking-wide">{t('findings.triageSection.title')}</h3>
          <div className="mt-2">
            <TriageBadge status={finding.triage_status} source={finding.triage_decision_source} />
          </div>
        </div>
        {finding.triage_decided_at && (
          <p className="text-xs text-gray-500">
            {t('findings.triageSection.decidedAt', { date: formatDateTime(finding.triage_decided_at, getAppLocale()) })}
          </p>
        )}
      </div>

      {canDecide && (
        <div className="flex flex-wrap gap-2">
          <button
            type="button"
            disabled={triageBusy}
            onClick={() => confirmMutation.mutate()}
            className="px-3 py-1.5 rounded-lg text-xs font-medium bg-brand-600 text-white hover:bg-brand-700 disabled:opacity-50"
          >
            {t('findings.triageSection.confirm')}
          </button>
          <button
            type="button"
            disabled={triageBusy}
            onClick={() => dismissMutation.mutate()}
            className="px-3 py-1.5 rounded-lg text-xs font-medium border border-gray-200 text-gray-700 hover:bg-gray-50 disabled:opacity-50"
          >
            {t('findings.triageSection.dismiss')}
          </button>
        </div>
      )}

      {finding.triage_status === 'dismissed' && isAdmin && (
        <button
          type="button"
          disabled={triageBusy}
          onClick={() => reopenMutation.mutate()}
          className="px-3 py-1.5 rounded-lg text-xs font-medium border border-amber-200 text-amber-800 hover:bg-amber-50 disabled:opacity-50"
        >
          {t('findings.triageSection.reopenAdmin')}
        </button>
      )}

      {finding.triage_status === 'confirmed' && (
        <p className="text-xs text-gray-500">
          {t('findings.triageSection.confirmedHint')}
        </p>
      )}

      {(confirmMutation.error || dismissMutation.error || reopenMutation.error) && (
        <p className="text-xs text-red-600">
          {(confirmMutation.error as { response?: { data?: { error?: string } } })?.response?.data?.error ??
            t('findings.triageSection.updateError')}
        </p>
      )}
    </div>
  )
}

function AIAnalysisSection({
  finding,
  autoAnalysisMinSeverity,
  onAnalyze,
  analyzing,
}: {
  finding: Finding
  autoAnalysisMinSeverity: 'critical' | 'high' | 'medium'
  onAnalyze: () => void
  analyzing: boolean
}) {
  const { t } = useTranslation()
  const analysisStatus = finding.ai_analysis_status
  const isPending = analysisStatus === 'pending' || analysisStatus === 'running'
  const isBelowAutoAnalysisThreshold = !meetsMinSeverity(finding.severity, autoAnalysisMinSeverity)
  const isPolicySkip =
    analysisStatus === 'skipped' &&
    Boolean(finding.ai_reasoning?.includes('below tenant auto-analysis threshold'))
  const reasoningText = finding.ai_reasoning_display ?? finding.ai_reasoning
  const exploitationText = finding.ai_exploitation_path_display ?? finding.ai_exploitation_path
  const remediationText = finding.ai_remediation_path_display ?? finding.ai_remediation_path

  return (
    <div className="rounded-xl border border-violet-100 bg-violet-50/50 p-4 space-y-3">
      <div className="flex items-center justify-between gap-3">
        <div className="flex items-center gap-2">
          <Sparkles className="w-4 h-4 text-violet-600" />
          <h3 className="text-xs font-semibold text-violet-800 uppercase tracking-wide">
            {t('findings.ai.title')}
          </h3>
        </div>
        <button
          onClick={onAnalyze}
          disabled={analyzing || isPending}
          className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium bg-violet-600 text-white hover:bg-violet-700 disabled:opacity-50"
        >
          <RefreshCw className={cn('w-3.5 h-3.5', (analyzing || isPending) && 'animate-spin')} />
          {isPending ? t('findings.ai.analyzing') : t('findings.ai.reanalyze')}
        </button>
      </div>

      {!analysisStatus && isBelowAutoAnalysisThreshold && (
        <p className="text-sm text-gray-600">
          {t('findings.ai.notRunBelowThreshold', {
            severity: finding.severity,
            minSeverity: autoAnalysisMinSeverity,
          })}
        </p>
      )}

      {!analysisStatus && !isBelowAutoAnalysisThreshold && (
        <p className="text-sm text-gray-600">{t('findings.ai.notRunYet')}</p>
      )}

      {analysisStatus === 'failed' && (
        <p className="text-sm text-red-600">
          {t('findings.ai.failed', {
            error: finding.ai_analysis_error ?? t('findings.ai.unknownError'),
          })}
        </p>
      )}

      {isPolicySkip && (
        <p className="text-sm text-gray-600">
          {t('findings.ai.policySkip', { reason: finding.ai_reasoning })}
        </p>
      )}

      {analysisStatus === 'skipped' && !isPolicySkip && (
        <p className="text-sm text-gray-600">{finding.ai_reasoning ?? t('findings.ai.skipped')}</p>
      )}

      {isPending && <p className="text-sm text-gray-600">{t('findings.ai.inProgress')}</p>}

      {(analysisStatus === 'completed' || analysisStatus === 'failed' || analysisStatus === 'skipped') && (
        <div className="flex flex-wrap gap-2">
          {finding.ai_criticality_verdict && (
            <CriticalityBadge verdict={finding.ai_criticality_verdict} />
          )}
          <ExploitabilityBadge
            verdict={finding.ai_exploitability_verdict}
            status={finding.ai_analysis_status}
          />
          {finding.ai_confidence != null && (
            <span className="inline-flex items-center rounded-full bg-white text-gray-600 ring-1 ring-inset ring-gray-200 px-2.5 py-1 text-xs">
              {t('findings.ai.confidence', { value: Math.round(finding.ai_confidence * 100) })}
            </span>
          )}
        </div>
      )}

      {reasoningText && analysisStatus === 'completed' && (
        <div>
          <p className="text-xs font-medium text-gray-500 mb-1">{t('findings.ai.reasoning')}</p>
          <p className="text-sm text-gray-700">{reasoningText}</p>
        </div>
      )}

      {exploitationText && analysisStatus === 'completed' && (
        <div>
          <p className="text-xs font-medium text-gray-500 mb-1">{t('findings.ai.exploitation')}</p>
          <p className="text-sm text-gray-700 whitespace-pre-wrap">{exploitationText}</p>
        </div>
      )}

      {remediationText && analysisStatus === 'completed' && (
        <div>
          <p className="text-xs font-medium text-gray-500 mb-1">{t('findings.ai.remediation')}</p>
          <p className="text-sm text-gray-700 whitespace-pre-wrap">{remediationText}</p>
        </div>
      )}

      {finding.ai_vulnerable_code_paths && finding.ai_vulnerable_code_paths.length > 0 && (
        <div>
          <p className="text-xs font-medium text-gray-500 mb-1">{t('findings.ai.vulnerablePaths')}</p>
          <ul className="space-y-1">
            {finding.ai_vulnerable_code_paths.map((codePath) => (
              <li key={codePath} className="text-sm font-mono text-gray-700">
                {finding.repo_full_name ? (
                  <a
                    href={`https://github.com/${finding.repo_full_name}/blob/HEAD/${codePath.split(':')[0]}${codePath.includes(':') ? `#L${codePath.split(':')[1]}` : ''}`}
                    target="_blank"
                    rel="noreferrer"
                    className="text-brand-600 hover:underline inline-flex items-center gap-1"
                  >
                    {codePath}
                    <ExternalLink className="w-3 h-3" />
                  </a>
                ) : (
                  codePath
                )}
              </li>
            ))}
          </ul>
        </div>
      )}
    </div>
  )
}

function RiskScoreSection({ finding }: { finding: Finding }) {
  const { t } = useTranslation()
  const isPartial = finding.risk_score != null && !finding.has_contextual_analysis

  return (
    <div className="rounded-xl border border-orange-100 bg-orange-50/40 p-4 space-y-2">
      <div className="flex items-center justify-between gap-3">
        <h3 className="text-xs font-semibold text-orange-800 uppercase tracking-wide">{t('findings.riskScore.title')}</h3>
        <RiskScoreBadge
          score={finding.risk_score}
          tier={finding.risk_tier}
          breached={finding.is_sla_breached}
          partial={isPartial}
        />
      </div>
      {isPartial ? (
        <p className="text-sm text-gray-600">
          {t('findings.riskScore.partialHint')}
        </p>
      ) : finding.has_contextual_analysis ? (
        <p className="text-sm text-gray-600">
          {t('findings.riskScore.contextualHint')}
        </p>
      ) : (
        <p className="text-sm text-gray-600">{t('findings.riskScore.baselineHint')}</p>
      )}
    </div>
  )
}

function CriticalityBadge({ verdict }: { verdict: CriticalityVerdict }) {
  const { t } = useTranslation()
  const labels: Record<CriticalityVerdict, string> = {
    true_critical: t('findings.criticality.true_critical'),
    false_positive: t('findings.criticality.false_positive'),
    informational: t('findings.criticality.informational'),
    needs_human_review: t('findings.criticality.needs_human_review'),
  }
  const colors: Record<CriticalityVerdict, string> = {
    true_critical: 'bg-red-50 text-red-700 ring-red-100',
    false_positive: 'bg-green-50 text-green-700 ring-green-100',
    informational: 'bg-gray-50 text-gray-600 ring-gray-200',
    needs_human_review: 'bg-amber-50 text-amber-700 ring-amber-100',
  }
  return (
    <span
      className={cn(
        'inline-flex items-center rounded-full ring-1 ring-inset px-2.5 py-1 text-xs font-medium',
        colors[verdict],
      )}
    >
      {labels[verdict]}
    </span>
  )
}


function PartialLabel() {
  const { t } = useTranslation()
  return <span className="text-[10px] font-medium text-amber-600">{t('findings.riskScore.partial')}</span>
}

function SlaLabel() {
  const { t } = useTranslation()
  return <span className="text-[10px] font-medium text-red-600">{t('findings.riskScore.sla')}</span>
}

function RiskScoreBadge({
  score,
  tier,
  breached,
  partial,
}: {
  score?: number
  tier?: RiskTier
  breached?: boolean
  partial?: boolean
}) {
  if (score == null) return <span className="text-xs text-gray-400">—</span>
  const tierColors: Record<RiskTier, string> = {
    critical: 'bg-red-50 text-red-700 ring-red-100',
    high: 'bg-orange-50 text-orange-700 ring-orange-100',
    medium: 'bg-yellow-50 text-yellow-700 ring-yellow-100',
    low: 'bg-gray-50 text-gray-600 ring-gray-200',
  }
  return (
    <span className="inline-flex items-center gap-1.5">
      <span
        className={cn(
          'inline-flex items-center rounded-full ring-1 ring-inset px-2 py-0.5 text-xs font-medium',
          tier ? tierColors[tier] : 'bg-gray-50 text-gray-600 ring-gray-200',
        )}
      >
        {score.toFixed(0)}
      </span>
      {partial && <PartialLabel />}
      {breached && <SlaLabel />}
    </span>
  )
}

function SortableTableHeader({
  label,
  field,
  currentSort,
  currentOrder,
  onSort,
}: {
  label: string
  field: FindingSortField
  currentSort: FindingSortField
  currentOrder: SortOrder
  onSort: (field: FindingSortField) => void
}) {
  const isActive = currentSort === field

  return (
    <th className="px-5 py-3 text-left font-medium text-gray-500">
      <button
        type="button"
        onClick={() => onSort(field)}
        className={cn(
          'inline-flex items-center gap-1 hover:text-gray-700 focus:outline-none focus-visible:ring-2 focus-visible:ring-brand-500 rounded',
          isActive && 'text-gray-700',
        )}
      >
        {label}
        {isActive &&
          (currentOrder === 'asc' ? (
            <ChevronUp className="w-3.5 h-3.5" />
          ) : (
            <ChevronDown className="w-3.5 h-3.5" />
          ))}
      </button>
    </th>
  )
}

function SourceEngineBadge({ engine }: { engine?: SourceEngine | string }) {
  const { t } = useTranslation()
  const value = engine ?? 'osv'
  const labels: Record<string, string> = {
    osv: t('findings.sourceBadge.osv'),
    manual: t('findings.sourceBadge.manual'),
    dataset: t('findings.sourceBadge.dataset'),
    guarddog: t('findings.sourceBadge.guarddog'),
    openssf_pa: t('findings.sourceBadge.openssf_pa'),
  }
  const colors: Record<string, string> = {
    osv: 'bg-blue-50 text-blue-700 ring-blue-100',
    manual: 'bg-violet-50 text-violet-700 ring-violet-100',
    dataset: 'bg-orange-50 text-orange-700 ring-orange-100',
    guarddog: 'bg-amber-50 text-amber-700 ring-amber-100',
    openssf_pa: 'bg-teal-50 text-teal-700 ring-teal-100',
  }

  return (
    <span
      className={cn(
        'inline-flex items-center rounded-full ring-1 ring-inset px-2.5 py-1 text-xs font-medium',
        colors[value] ?? 'bg-gray-50 text-gray-600 ring-gray-200',
      )}
    >
      {labels[value] ?? value}
    </span>
  )
}

function TriageBadge({
  status,
  source,
}: {
  status?: TriageStatus
  source?: Finding['triage_decision_source']
}) {
  const { t } = useTranslation()
  if (!status) return <span className="text-xs text-gray-400">—</span>

  const labels: Record<TriageStatus, string> = {
    new: t('findings.triageBadge.new'),
    needs_review: t('findings.triageBadge.needsReview'),
    confirmed: t('findings.triageBadge.confirmed'),
    dismissed: t('findings.triageBadge.dismissed'),
  }
  const colors: Record<TriageStatus, string> = {
    new: 'bg-slate-50 text-slate-700 ring-slate-200',
    needs_review: 'bg-amber-50 text-amber-700 ring-amber-100',
    confirmed: 'bg-green-50 text-green-700 ring-green-100',
    dismissed: 'bg-gray-100 text-gray-600 ring-gray-200',
  }

  return (
    <span className="inline-flex items-center gap-1">
      <span
        className={cn(
          'inline-flex items-center rounded-full ring-1 ring-inset px-2.5 py-1 text-xs font-medium',
          colors[status],
        )}
      >
        {labels[status]}
      </span>
      {source === 'auto_ai' && status === 'confirmed' && (
        <span className="text-[10px] text-violet-600">{t('findings.triageBadge.ai')}</span>
      )}
    </span>
  )
}

function ReachabilityBadge({ status }: { status?: ReachabilityStatus }) {
  const { t } = useTranslation()
  if (!status) return <span className="text-xs text-gray-400">{t('findings.reachability.unknown')}</span>
  const labels: Record<ReachabilityStatus, string> = {
    reachable: t('findings.reachability.reachable'),
    unreachable: t('findings.reachability.unreachable'),
    unknown: t('findings.reachability.unknown'),
  }
  const colors: Record<ReachabilityStatus, string> = {
    reachable: 'text-red-700 font-medium',
    unreachable: 'text-gray-500',
    unknown: 'text-gray-400',
  }
  return <span className={cn('text-xs', colors[status])}>{labels[status]}</span>
}

function ExploitabilityBadge({
  verdict,
  status,
}: {
  verdict?: ExploitabilityVerdict
  status?: AnalysisStatus
}) {
  const { t } = useTranslation()
  if (!status) return <span className="text-xs text-gray-400">—</span>
  if (status === 'pending' || status === 'running') {
    return <span className="text-xs text-violet-600">{t('findings.exploitability.pending')}</span>
  }
  if (status === 'failed') return <span className="text-xs text-red-500">{t('findings.exploitability.error')}</span>
  if (status === 'skipped') return <span className="text-xs text-gray-400">{t('findings.exploitability.na')}</span>
  if (!verdict) return <span className="text-xs text-gray-400">—</span>

  const labels: Record<ExploitabilityVerdict, string> = {
    none: t('findings.exploitability.none'),
    low: t('findings.exploitability.low'),
    medium: t('findings.exploitability.medium'),
    high: t('findings.exploitability.high'),
    critical: t('findings.exploitability.critical'),
  }
  const colors: Record<ExploitabilityVerdict, string> = {
    none: 'text-gray-500',
    low: 'text-yellow-600',
    medium: 'text-orange-600',
    high: 'text-red-600',
    critical: 'text-red-700 font-medium',
  }
  return <span className={cn('text-xs', colors[verdict])}>{labels[verdict]}</span>
}

function InfoField({
  label,
  value,
  mono,
  highlight,
}: {
  label: string
  value: string
  mono?: boolean
  highlight?: boolean
}) {
  return (
    <div>
      <p className="text-xs text-gray-500 mb-0.5">{label}</p>
      <p className={`text-sm truncate ${mono ? 'font-mono' : ''} ${highlight ? 'text-green-700 font-medium' : 'text-gray-900'}`}>
        {value}
      </p>
    </div>
  )
}

function asString(value: unknown): string {
  return typeof value === 'string' ? value : ''
}

function asSeverity(value: unknown): Severity | '' {
  if (value === 'critical' || value === 'high' || value === 'medium' || value === 'low' || value === 'unknown') {
    return value
  }
  return ''
}

function asStatus(value: unknown): FindingStatus | '' {
  if (value === 'open' || value === 'suppressed' || value === 'fixed') return value
  return ''
}

function asTriageStatus(value: unknown): TriageStatus | '' | 'pending' {
  if (value === 'pending') return 'pending'
  if (value === 'new' || value === 'needs_review' || value === 'confirmed' || value === 'dismissed') {
    return value
  }
  return ''
}

function asSourceEngine(value: unknown): SourceEngine | '' {
  if (
    value === 'osv' ||
    value === 'manual' ||
    value === 'dataset' ||
    value === 'guarddog' ||
    value === 'openssf_pa'
  ) {
    return value
  }
  return ''
}

function asSortField(value: unknown): FindingSortField {
  if (
    value === 'severity' ||
    value === 'status' ||
    value === 'last_seen_at' ||
    value === 'first_seen_at' ||
    value === 'cvss_score' ||
    value === 'package_name' ||
    value === 'risk_score'
  ) {
    return value
  }
  return 'risk_score'
}

function asReachability(value: unknown): ReachabilityStatus | '' {
  if (value === 'reachable' || value === 'unreachable' || value === 'unknown') return value
  return ''
}

function asRiskTier(value: unknown): RiskTier | '' {
  if (value === 'critical' || value === 'high' || value === 'medium' || value === 'low') return value
  return ''
}

function asSortOrder(value: unknown): SortOrder {
  return value === 'asc' ? 'asc' : 'desc'
}

function asPageSize(value: unknown): number {
  if (typeof value === 'number' && [10, 20, 50, 100].includes(value)) return value
  return 20
}
