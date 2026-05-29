import { useMemo, useState } from 'react'
import { Link } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import { useTranslation } from 'react-i18next'
import { Activity, RefreshCw } from 'lucide-react'
import { listScanJobs, getScanJobsSummary, type ScanJobStatus } from '@/api/scanJobs'
import { listRepos } from '@/api/repos'
import { PageSpinner } from '@/components/shared/Spinner'
import { EmptyState } from '@/components/shared/EmptyState'
import ScanStatusBadge, { useScanTriggeredByLabel } from '@/components/shared/ScanStatusBadge'
import { getAppLocale } from '@/i18n'
import { formatDateTime } from '@/lib/locale'
import { cn } from '@/lib/utils'

const POLL_MS = 5000

export default function ScansPage() {
  const { t } = useTranslation()
  const triggeredByLabel = useScanTriggeredByLabel()
  const locale = getAppLocale()
  const [statusFilter, setStatusFilter] = useState<ScanJobStatus | ''>('')
  const [repoFilter, setRepoFilter] = useState('')
  const [page, setPage] = useState(1)

  const { data: summary } = useQuery({
    queryKey: ['scan-jobs-summary'],
    queryFn: getScanJobsSummary,
    refetchInterval: (query) =>
      (query.state.data?.total_active ?? 0) > 0 ? POLL_MS : false,
  })

  const hasActiveScans = (summary?.total_active ?? 0) > 0

  const { data: repos = [] } = useQuery({
    queryKey: ['repos', '', ''],
    queryFn: () => listRepos(),
  })

  const { data, isLoading, isFetching } = useQuery({
    queryKey: ['scan-jobs', statusFilter, repoFilter, page],
    queryFn: () =>
      listScanJobs({
        status: statusFilter || undefined,
        repo_id: repoFilter || undefined,
        page,
        per_page: 50,
      }),
    refetchInterval: hasActiveScans ? POLL_MS : false,
  })

  const totalPages = useMemo(() => {
    if (!data) return 1
    return Math.max(1, Math.ceil(data.total / data.per_page))
  }, [data])

  if (isLoading && !data) return <PageSpinner />

  const jobs = data?.items ?? []

  return (
    <div className="space-y-4">
      {hasActiveScans && (
        <div className="flex items-center justify-between gap-3 rounded-xl border border-blue-200 bg-blue-50 px-4 py-3 text-sm text-blue-900">
          <div className="flex items-center gap-2">
            <Activity className="w-4 h-4" />
            <span>
              {t('scans.activeScans', {
                pending: summary?.pending ?? 0,
                running: summary?.running ?? 0,
              })}
            </span>
          </div>
          {isFetching && (
            <span className="inline-flex items-center gap-1 text-xs text-blue-700">
              <RefreshCw className="w-3.5 h-3.5 animate-spin" /> {t('common.updating')}
            </span>
          )}
        </div>
      )}

      <div className="flex items-center justify-between gap-3 flex-wrap">
        <div className="flex items-center gap-3 flex-wrap">
          <label className="text-sm text-gray-600 font-medium">{t('scans.statusLabel')}</label>
          <select
            value={statusFilter}
            onChange={(e) => {
              setStatusFilter(e.target.value as ScanJobStatus | '')
              setPage(1)
            }}
            className="text-sm border border-gray-200 rounded-lg px-3 py-1.5 bg-white focus:outline-none focus:ring-2 focus:ring-brand-500"
          >
            <option value="">{t('scans.statusAll')}</option>
            <option value="pending">{t('scans.statusPending')}</option>
            <option value="running">{t('scans.statusRunning')}</option>
            <option value="completed">{t('scans.statusCompleted')}</option>
            <option value="failed">{t('scans.statusFailed')}</option>
          </select>

          <label className="text-sm text-gray-600 font-medium">{t('scans.repositoryLabel')}</label>
          <select
            value={repoFilter}
            onChange={(e) => {
              setRepoFilter(e.target.value)
              setPage(1)
            }}
            className="text-sm border border-gray-200 rounded-lg px-3 py-1.5 bg-white focus:outline-none focus:ring-2 focus:ring-brand-500 max-w-xs"
          >
            <option value="">{t('common.all')}</option>
            {repos.map((repo) => (
              <option key={repo.id} value={repo.id}>
                {repo.full_name}
              </option>
            ))}
          </select>
        </div>

        <Link to="/repositories" className="text-sm text-brand-700 hover:text-brand-800 font-medium">
          {t('scans.viewRepositories')}
        </Link>
      </div>

      {jobs.length === 0 ? (
        <div className="bg-white rounded-xl border border-gray-200">
          <EmptyState
            icon={Activity}
            title={t('scans.emptyTitle')}
            description={t('scans.emptyDescription')}
          />
        </div>
      ) : (
        <div className="bg-white rounded-xl border border-gray-200 overflow-hidden">
          <div className="px-6 py-4 border-b border-gray-100 flex items-center justify-between">
            <h2 className="font-semibold text-gray-900">
              {t('scans.count', { count: data?.total ?? jobs.length })}
            </h2>
            {isFetching && !hasActiveScans && (
              <span className="inline-flex items-center gap-1 text-xs text-gray-500">
                <RefreshCw className="w-3.5 h-3.5 animate-spin" /> {t('common.updating')}
              </span>
            )}
          </div>
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-gray-100 bg-gray-50">
                  <th className="px-6 py-3 text-left font-medium text-gray-500">{t('scans.columns.repository')}</th>
                  <th className="px-6 py-3 text-left font-medium text-gray-500">{t('scans.columns.status')}</th>
                  <th className="px-6 py-3 text-left font-medium text-gray-500">{t('scans.columns.source')}</th>
                  <th className="px-6 py-3 text-left font-medium text-gray-500">{t('scans.columns.started')}</th>
                  <th className="px-6 py-3 text-left font-medium text-gray-500">{t('scans.columns.completed')}</th>
                  <th className="px-6 py-3 text-left font-medium text-gray-500">{t('scans.columns.error')}</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-50">
                {jobs.map((job) => (
                  <tr key={job.id} className="hover:bg-gray-50 transition-colors">
                    <td className="px-6 py-3 font-medium text-gray-900">{job.repo_full_name}</td>
                    <td className="px-6 py-3">
                      <ScanStatusBadge status={job.status} />
                    </td>
                    <td className="px-6 py-3 text-gray-600">{triggeredByLabel(job.triggered_by)}</td>
                    <td className="px-6 py-3 text-gray-500">
                      {job.started_at ? formatDateTime(job.started_at, locale) : '—'}
                    </td>
                    <td className="px-6 py-3 text-gray-500">
                      {job.completed_at ? formatDateTime(job.completed_at, locale) : '—'}
                    </td>
                    <td
                      className="px-6 py-3 text-red-600 text-xs max-w-xs truncate"
                      title={job.error_msg ?? undefined}
                    >
                      {job.error_msg ?? '—'}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          {totalPages > 1 && (
            <div className="px-6 py-3 border-t border-gray-100 flex items-center justify-between text-sm">
              <span className="text-gray-500">{t('common.pageOf', { page, total: totalPages })}</span>
              <div className="flex items-center gap-2">
                <button
                  type="button"
                  disabled={page <= 1}
                  onClick={() => setPage((p) => p - 1)}
                  className={cn(
                    'px-3 py-1.5 rounded-lg border text-xs font-medium transition-colors',
                    page <= 1
                      ? 'border-gray-100 text-gray-300 cursor-not-allowed'
                      : 'border-gray-200 text-gray-700 hover:bg-gray-50',
                  )}
                >
                  {t('common.previous')}
                </button>
                <button
                  type="button"
                  disabled={page >= totalPages}
                  onClick={() => setPage((p) => p + 1)}
                  className={cn(
                    'px-3 py-1.5 rounded-lg border text-xs font-medium transition-colors',
                    page >= totalPages
                      ? 'border-gray-100 text-gray-300 cursor-not-allowed'
                      : 'border-gray-200 text-gray-700 hover:bg-gray-50',
                  )}
                >
                  {t('common.next')}
                </button>
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  )
}
