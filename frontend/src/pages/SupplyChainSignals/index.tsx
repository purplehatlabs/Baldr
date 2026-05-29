import { useMemo, useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { useTranslation } from 'react-i18next'
import { AlertTriangle, RefreshCw, Search, X } from 'lucide-react'
import { listRepos } from '@/api/repos'
import {
  getSupplyChainSignalById,
  getSupplyChainSignalsSummary,
  listSupplyChainSignals,
  type SupplyChainSignal,
  type SupplyChainSignalStatus,
  type SupplyChainSignalType,
} from '@/api/supplyChainSignals'
import type { Severity } from '@/api/findings'
import { EmptyState } from '@/components/shared/EmptyState'
import { SeverityBadge } from '@/components/shared/SeverityBadge'
import { PageSpinner } from '@/components/shared/Spinner'
import { getAppLocale } from '@/i18n'
import { formatDateTime } from '@/lib/locale'
import { cn } from '@/lib/utils'

function useSupplyChainFilterOptions() {
  const { t } = useTranslation()

  return useMemo(
    () => ({
      statusOptions: [
        { value: '' as SupplyChainSignalStatus | '', label: t('supplyChainSignals.filters.allStatuses') },
        { value: 'open' as const, label: t('supplyChainSignals.status.open') },
        { value: 'triaged' as const, label: t('supplyChainSignals.status.triaged') },
        { value: 'suppressed' as const, label: t('supplyChainSignals.status.suppressed') },
        { value: 'resolved' as const, label: t('supplyChainSignals.status.resolved') },
      ],
      signalTypeOptions: [
        { value: '' as SupplyChainSignalType | '', label: t('supplyChainSignals.filters.allTypes') },
        { value: 'malicious_package' as const, label: t('supplyChainSignals.signalType.malicious_package') },
        { value: 'typosquat' as const, label: t('supplyChainSignals.signalType.typosquat') },
        { value: 'dependency_confusion' as const, label: t('supplyChainSignals.signalType.dependency_confusion') },
        { value: 'suspicious_behavior' as const, label: t('supplyChainSignals.signalType.suspicious_behavior') },
      ],
      severityOptions: [
        { value: '' as Severity | '', label: t('findings.filters.allSeverities') },
        { value: 'critical' as const, label: t('findings.severity.critical') },
        { value: 'high' as const, label: t('findings.severity.high') },
        { value: 'medium' as const, label: t('findings.severity.medium') },
        { value: 'low' as const, label: t('findings.severity.low') },
        { value: 'unknown' as const, label: t('findings.severity.unknown') },
      ],
      engineOptions: [
        { value: '', label: t('supplyChainSignals.filters.allEngines') },
        { value: 'dataset', label: t('supplyChainSignals.engine.dataset') },
        { value: 'guarddog', label: t('supplyChainSignals.engine.guarddog') },
        { value: 'openssf_pa', label: t('supplyChainSignals.engine.openssf_pa') },
        { value: 'manual', label: t('supplyChainSignals.engine.manual') },
      ],
    }),
    [t],
  )
}

function toSignalTypeLabel(value: string): string {
  if (!value) return '—'
  return value.split('_').join(' ')
}

function statusClassName(value: string): string {
  if (value === 'open') return 'bg-red-50 text-red-700 ring-red-100'
  if (value === 'triaged') return 'bg-blue-50 text-blue-700 ring-blue-100'
  if (value === 'suppressed') return 'bg-gray-100 text-gray-600 ring-gray-200'
  if (value === 'resolved') return 'bg-green-50 text-green-700 ring-green-100'
  return 'bg-gray-100 text-gray-600 ring-gray-200'
}

function isSeverity(value: string): value is Severity {
  return (
    value === 'critical' ||
    value === 'high' ||
    value === 'medium' ||
    value === 'low' ||
    value === 'unknown'
  )
}

function prettyJSON(value: unknown): string {
  if (value == null) return '{}'
  if (typeof value === 'string') {
    try {
      return JSON.stringify(JSON.parse(value), null, 2)
    } catch {
      return value
    }
  }
  try {
    return JSON.stringify(value, null, 2)
  } catch {
    return '{}'
  }
}

export default function SupplyChainSignalsPage() {
  const { t } = useTranslation()
  const locale = getAppLocale()
  const { statusOptions, signalTypeOptions, severityOptions, engineOptions } = useSupplyChainFilterOptions()

  const [status, setStatus] = useState<SupplyChainSignalStatus | ''>('')
  const [engine, setEngine] = useState('')
  const [signalType, setSignalType] = useState<SupplyChainSignalType | ''>('')
  const [severity, setSeverity] = useState<Severity | ''>('')
  const [repoId, setRepoId] = useState('')
  const [qInput, setQInput] = useState('')
  const [q, setQ] = useState('')
  const [page, setPage] = useState(1)
  const [pageSize, setPageSize] = useState(20)
  const [selectedId, setSelectedId] = useState<string | null>(null)

  const { data: repos = [] } = useQuery({
    queryKey: ['repos'],
    queryFn: () => listRepos(),
  })

  const { data: signalsPage, isLoading, isFetching, isError, error, refetch } = useQuery({
    queryKey: [
      'supply-chain-signals',
      status,
      engine,
      signalType,
      severity,
      repoId,
      q,
      page,
      pageSize,
    ],
    queryFn: () =>
      listSupplyChainSignals({
        status: status || undefined,
        engine: engine || undefined,
        signal_type: signalType || undefined,
        severity: severity || undefined,
        repo_id: repoId || undefined,
        q: q || undefined,
        page,
        per_page: pageSize,
      }),
  })

  const { data: summary } = useQuery({
    queryKey: [
      'supply-chain-signals-summary',
      status,
      engine,
      signalType,
      severity,
      repoId,
      q,
    ],
    queryFn: () =>
      getSupplyChainSignalsSummary({
        status: status || undefined,
        engine: engine || undefined,
        signal_type: signalType || undefined,
        severity: severity || undefined,
        repo_id: repoId || undefined,
        q: q || undefined,
      }),
  })

  const items = signalsPage?.items ?? []
  const total = signalsPage?.total ?? 0
  const totalPages = signalsPage?.total_pages ?? 0
  const sortedRepos = useMemo(
    () => [...repos].sort((a, b) => a.full_name.localeCompare(b.full_name)),
    [repos],
  )
  const selectedSignal = useMemo(
    () => items.find((item) => item.id === selectedId) ?? null,
    [items, selectedId],
  )

  const statusLabel = (value: string) => {
    if (!value) return '—'
    const key = `supplyChainSignals.status.${value}` as const
    if (value === 'open' || value === 'triaged' || value === 'suppressed' || value === 'resolved') {
      return t(key)
    }
    return value
  }

  if (isLoading) return <PageSpinner />

  const from = total === 0 ? 0 : (page - 1) * pageSize + 1
  const to = total === 0 ? 0 : Math.min(page * pageSize, total)
  const openCount = summary?.by_status.open ?? 0
  const criticalAndHighCount =
    (summary?.by_severity.critical ?? 0) + (summary?.by_severity.high ?? 0)

  return (
    <div className="space-y-4">
      <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
        <SummaryCard label={t('supplyChainSignals.summary.total')} value={summary?.total ?? total} />
        <SummaryCard label={t('supplyChainSignals.summary.open')} value={openCount} />
        <SummaryCard label={t('supplyChainSignals.summary.criticalHigh')} value={criticalAndHighCount} />
      </div>

      <div className="bg-white rounded-xl border border-gray-200 p-4 space-y-3">
        <div className="flex flex-wrap items-center gap-3">
          <div className="relative min-w-[240px] flex-1">
            <Search className="w-4 h-4 text-gray-400 absolute left-3 top-1/2 -translate-y-1/2" />
            <input
              value={qInput}
              onChange={(event) => setQInput(event.target.value)}
              onKeyDown={(event) => {
                if (event.key === 'Enter') {
                  setPage(1)
                  setQ(qInput.trim())
                }
              }}
              placeholder={t('supplyChainSignals.searchPlaceholder')}
              className="w-full text-sm border border-gray-200 rounded-lg pl-9 pr-3 py-2 bg-white focus:outline-none focus:ring-2 focus:ring-brand-500"
            />
          </div>
          <button
            onClick={() => {
              setPage(1)
              setQ(qInput.trim())
            }}
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
            value={status}
            onChange={(event) => {
              setStatus(event.target.value as SupplyChainSignalStatus | '')
              setPage(1)
            }}
            className="text-sm border border-gray-200 rounded-lg px-3 py-1.5 bg-white focus:outline-none focus:ring-2 focus:ring-brand-500"
          >
            {statusOptions.map((option) => (
              <option key={option.value || 'all'} value={option.value}>
                {option.label}
              </option>
            ))}
          </select>

          <select
            value={signalType}
            onChange={(event) => {
              setSignalType(event.target.value as SupplyChainSignalType | '')
              setPage(1)
            }}
            className="text-sm border border-gray-200 rounded-lg px-3 py-1.5 bg-white focus:outline-none focus:ring-2 focus:ring-brand-500"
          >
            {signalTypeOptions.map((option) => (
              <option key={option.value || 'all'} value={option.value}>
                {option.label}
              </option>
            ))}
          </select>

          <select
            value={severity}
            onChange={(event) => {
              setSeverity(event.target.value as Severity | '')
              setPage(1)
            }}
            className="text-sm border border-gray-200 rounded-lg px-3 py-1.5 bg-white focus:outline-none focus:ring-2 focus:ring-brand-500"
          >
            {severityOptions.map((option) => (
              <option key={option.value || 'all'} value={option.value}>
                {option.label}
              </option>
            ))}
          </select>

          {sortedRepos.length > 0 && (
            <select
              value={repoId}
              onChange={(event) => {
                setRepoId(event.target.value)
                setPage(1)
              }}
              className="text-sm border border-gray-200 rounded-lg px-3 py-1.5 bg-white focus:outline-none focus:ring-2 focus:ring-brand-500 min-w-[220px]"
            >
              <option value="">{t('supplyChainSignals.filters.allRepos')}</option>
              {sortedRepos.map((repo) => (
                <option key={repo.id} value={repo.id}>
                  {repo.full_name}
                </option>
              ))}
            </select>
          )}

          <select
            value={engine}
            onChange={(event) => {
              setEngine(event.target.value)
              setPage(1)
            }}
            className="text-sm border border-gray-200 rounded-lg px-3 py-1.5 bg-white focus:outline-none focus:ring-2 focus:ring-brand-500"
          >
            {engineOptions.map((option) => (
              <option key={option.value || 'all'} value={option.value}>
                {option.label}
              </option>
            ))}
          </select>

          <button
            onClick={() => refetch()}
            disabled={isFetching}
            className="inline-flex items-center gap-1.5 text-sm border border-gray-200 rounded-lg px-3 py-1.5 bg-white hover:bg-gray-50 disabled:opacity-50"
          >
            <RefreshCw className={cn('w-3.5 h-3.5', isFetching && 'animate-spin')} />
            {t('common.refresh')}
          </button>

          <span className="ml-auto text-sm text-gray-500 self-center">
            {t('supplyChainSignals.count', { count: total })}
          </span>
        </div>
      </div>

      {isError && (
        <div className="rounded-lg border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-700">
          {t('supplyChainSignals.loadError')}
          {error instanceof Error && error.message ? ` ${error.message}` : ''}
        </div>
      )}

      {items.length === 0 ? (
        <div className="bg-white rounded-xl border border-gray-200">
          <EmptyState
            icon={AlertTriangle}
            title={t('supplyChainSignals.emptyTitle')}
            description={t('supplyChainSignals.emptyDescription')}
          />
        </div>
      ) : (
        <div className="bg-white rounded-xl border border-gray-200 overflow-hidden">
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-gray-100 bg-gray-50">
                  <th className="px-5 py-3 text-left font-medium text-gray-500">{t('supplyChainSignals.columns.package')}</th>
                  <th className="px-5 py-3 text-left font-medium text-gray-500">{t('supplyChainSignals.columns.version')}</th>
                  <th className="px-5 py-3 text-left font-medium text-gray-500">{t('supplyChainSignals.columns.ecosystem')}</th>
                  <th className="px-5 py-3 text-left font-medium text-gray-500">{t('supplyChainSignals.columns.type')}</th>
                  <th className="px-5 py-3 text-left font-medium text-gray-500">{t('supplyChainSignals.columns.severity')}</th>
                  <th className="px-5 py-3 text-left font-medium text-gray-500">{t('supplyChainSignals.columns.engine')}</th>
                  <th className="px-5 py-3 text-left font-medium text-gray-500">{t('supplyChainSignals.columns.status')}</th>
                  <th className="px-5 py-3 text-left font-medium text-gray-500">{t('supplyChainSignals.columns.repo')}</th>
                  <th className="px-5 py-3 text-left font-medium text-gray-500">{t('supplyChainSignals.columns.lastSeen')}</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-50">
                {items.map((signal) => (
                  <tr
                    key={signal.id}
                    className="hover:bg-gray-50 cursor-pointer transition-colors"
                    onClick={() => setSelectedId(signal.id)}
                  >
                    <td className="px-5 py-3 font-medium text-gray-900">{signal.package_name || '—'}</td>
                    <td className="px-5 py-3 text-gray-600 font-mono">{signal.package_version || '—'}</td>
                    <td className="px-5 py-3 text-gray-600">{signal.package_ecosystem || '—'}</td>
                    <td className="px-5 py-3 text-gray-600">{toSignalTypeLabel(signal.signal_type)}</td>
                    <td className="px-5 py-3">
                      <SeverityBadge
                        severity={isSeverity(signal.severity) ? signal.severity : 'unknown'}
                      />
                    </td>
                    <td className="px-5 py-3 text-gray-600 font-mono">{signal.source_engine || '—'}</td>
                    <td className="px-5 py-3">
                      <span
                        className={cn(
                          'inline-flex items-center rounded-full ring-1 ring-inset px-2.5 py-1 text-xs font-medium',
                          statusClassName(signal.status),
                        )}
                      >
                        {statusLabel(signal.status)}
                      </span>
                    </td>
                    <td className="px-5 py-3 text-gray-600 max-w-[220px] truncate" title={signal.repo_full_name || undefined}>
                      {signal.repo_full_name || '—'}
                    </td>
                    <td className="px-5 py-3 text-gray-500">
                      {signal.last_seen_at ? formatDateTime(signal.last_seen_at, locale) : '—'}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
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
          </button>
        </div>
      </div>

      {selectedId && (
        <SupplyChainSignalDetail
          signalId={selectedId}
          fallbackSignal={selectedSignal}
          onClose={() => setSelectedId(null)}
        />
      )}
    </div>
  )
}

function SummaryCard({ label, value }: { label: string; value: number }) {
  return (
    <div className="rounded-xl border border-gray-200 bg-white px-4 py-3">
      <p className="text-xs uppercase tracking-wide text-gray-500">{label}</p>
      <p className="mt-1 text-2xl font-semibold text-gray-900">{value}</p>
    </div>
  )
}

function SupplyChainSignalDetail({
  signalId,
  fallbackSignal,
  onClose,
}: {
  signalId: string
  fallbackSignal: SupplyChainSignal | null
  onClose: () => void
}) {
  const { t } = useTranslation()
  const locale = getAppLocale()

  const { data, isLoading, isError } = useQuery({
    queryKey: ['supply-chain-signal', signalId],
    queryFn: () => getSupplyChainSignalById(signalId),
    enabled: Boolean(signalId),
    retry: false,
  })

  const signal = data ?? fallbackSignal

  const statusLabel = (value: string) => {
    if (!value) return '—'
    const key = `supplyChainSignals.status.${value}` as const
    if (value === 'open' || value === 'triaged' || value === 'suppressed' || value === 'resolved') {
      return t(key)
    }
    return value
  }

  if (isLoading && !signal) {
    return (
      <div className="fixed inset-0 z-50 flex justify-end" onClick={onClose}>
        <div
          className="relative w-full max-w-xl bg-white shadow-xl h-full border-l border-gray-200 flex items-center justify-center"
          onClick={(event) => event.stopPropagation()}
        >
          <PageSpinner />
        </div>
      </div>
    )
  }

  if (!signal) return null

  const evidenceText = prettyJSON(signal.evidence_json ?? signal.metadata_json ?? {})
  const severity = isSeverity(signal.severity) ? signal.severity : 'unknown'

  return (
    <div className="fixed inset-0 z-50 flex justify-end" onClick={onClose}>
      <div
        className="relative w-full max-w-xl bg-white shadow-xl h-full overflow-y-auto border-l border-gray-200"
        onClick={(event) => event.stopPropagation()}
      >
        <div className="sticky top-0 bg-white border-b border-gray-100 px-6 py-4 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <SeverityBadge severity={severity} />
            <span className="font-semibold text-gray-900 truncate">
              {signal.package_name}@{signal.package_version}
            </span>
          </div>
          <button onClick={onClose} className="p-1 rounded-lg hover:bg-gray-100">
            <X className="w-5 h-5 text-gray-500" />
          </button>
        </div>

        <div className="p-6 space-y-6">
          {isError && fallbackSignal && (
            <div className="rounded-lg border border-amber-200 bg-amber-50 px-3 py-2 text-xs text-amber-800">
              {t('supplyChainSignals.detailUnavailable')}
            </div>
          )}

          <div className="grid grid-cols-2 gap-4">
            <InfoField label={t('supplyChainSignals.fields.signalKey')} value={signal.signal_key || '—'} mono />
            <InfoField label={t('supplyChainSignals.fields.signalType')} value={toSignalTypeLabel(signal.signal_type)} />
            <InfoField label={t('supplyChainSignals.fields.status')} value={statusLabel(signal.status)} />
            <InfoField label={t('supplyChainSignals.fields.engine')} value={signal.source_engine || '—'} mono />
            <InfoField label={t('supplyChainSignals.fields.ecosystem')} value={signal.package_ecosystem || '—'} />
            <InfoField label={t('supplyChainSignals.fields.repository')} value={signal.repo_full_name || '—'} />
            <InfoField
              label={t('supplyChainSignals.fields.lastSeen')}
              value={signal.last_seen_at ? formatDateTime(signal.last_seen_at, locale) : '—'}
            />
            <InfoField
              label={t('supplyChainSignals.fields.confidence')}
              value={signal.confidence != null ? `${Math.round(signal.confidence * 100)}%` : '—'}
            />
          </div>

          <div>
            <h3 className="text-xs font-semibold text-gray-500 uppercase tracking-wide mb-2">
              {t('supplyChainSignals.reasoning')}
            </h3>
            <p className="text-sm text-gray-700 whitespace-pre-wrap">
              {signal.reasoning || t('supplyChainSignals.noReasoning')}
            </p>
          </div>

          <div>
            <h3 className="text-xs font-semibold text-gray-500 uppercase tracking-wide mb-2">
              {t('supplyChainSignals.evidenceJson')}
            </h3>
            <pre className="text-xs text-gray-700 bg-gray-50 border border-gray-200 rounded-lg p-3 overflow-x-auto whitespace-pre-wrap">
              {evidenceText}
            </pre>
          </div>
        </div>
      </div>
    </div>
  )
}

function InfoField({
  label,
  value,
  mono,
}: {
  label: string
  value: string
  mono?: boolean
}) {
  return (
    <div>
      <p className="text-xs text-gray-500 mb-0.5">{label}</p>
      <p className={cn('text-sm text-gray-900 truncate', mono && 'font-mono')}>{value}</p>
    </div>
  )
}
