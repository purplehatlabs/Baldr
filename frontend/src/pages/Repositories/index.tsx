import { useEffect, useMemo, useRef, useState } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import {
  useInfiniteQuery,
  useMutation,
  useQuery,
  useQueryClient,
} from '@tanstack/react-query'
import {
  Activity,
  AlertCircle,
  CheckCircle,
  Download,
  GitBranch,
  Github,
  Loader,
  Lock,
  Play,
  RefreshCw,
  Search,
  ShieldAlert,
  X,
} from 'lucide-react'
import { useTranslation } from 'react-i18next'
import {
  getScanApiErrorMessage,
  isRepoScanActive,
  listRepos,
  rescanAllRepos,
  triggerScan,
  updateRepoExposure,
  type Repo,
} from '@/api/repos'
import {
  listGitHubRepos,
  listOrgs,
  scanGitHubReposBatch,
  syncOrgRepos,
  type GitHubRepo,
  type Org,
} from '@/api/orgs'
import { getScanJobsSummary } from '@/api/scanJobs'
import { EmptyState } from '@/components/shared/EmptyState'
import ScanStatusBadge from '@/components/shared/ScanStatusBadge'
import { PageSpinner } from '@/components/shared/Spinner'
import { getAppLocale } from '@/i18n'
import { formatDateTime } from '@/lib/locale'
import { cn } from '@/lib/utils'

const BROWSE_PER_PAGE = 50
const BROWSE_STALE_MS = 5 * 60 * 1000
const SCAN_BATCH_MAX = 200
const SCAN_POLL_MS = 5000

type RepoExposureUpdateInput = {
  repoId: string
  isInternetExposed: boolean
  assetCriticality: Repo['asset_criticality']
  dataSensitivity: Repo['data_sensitivity']
  environment: Repo['environment']
}

export default function RepositoriesPage() {
  const { t } = useTranslation()
  const [selectedOrg, setSelectedOrg] = useState<string>('')
  const [exposureFilter, setExposureFilter] = useState<
    'pending' | 'internet' | 'internal' | ''
  >('')
  const [browseOrg, setBrowseOrg] = useState<Org | null>(null)
  const [scanFeedback, setScanFeedback] = useState<string | null>(null)
  const queryClient = useQueryClient()

  const { data: orgs = [] } = useQuery({
    queryKey: ['orgs'],
    queryFn: listOrgs,
  })

  const { data: scanSummary } = useQuery({
    queryKey: ['scan-jobs-summary'],
    queryFn: getScanJobsSummary,
    refetchInterval: (query) =>
      (query.state.data?.total_active ?? 0) > 0 ? SCAN_POLL_MS : false,
  })

  const hasActiveScans = (scanSummary?.total_active ?? 0) > 0

  const {
    data: repos = [],
    isFetching,
    isLoading,
  } = useQuery({
    queryKey: ['repos', selectedOrg, exposureFilter],
    queryFn: () => listRepos(selectedOrg || undefined, exposureFilter || undefined),
    refetchInterval: hasActiveScans ? SCAN_POLL_MS : false,
  })

  const scanMutation = useMutation({
    mutationFn: triggerScan,
    onSuccess: () => {
      setScanFeedback(null)
      queryClient.invalidateQueries({ queryKey: ['scan-jobs'] })
      queryClient.invalidateQueries({ queryKey: ['scan-jobs-summary'] })
      setTimeout(() => queryClient.invalidateQueries({ queryKey: ['repos'] }), 1500)
    },
    onError: (error) => {
      setScanFeedback(getScanApiErrorMessage(error) ?? t('repositories.scanEnqueueError'))
    },
  })

  const rescanAllMutation = useMutation({
    mutationFn: () => rescanAllRepos(selectedOrg || undefined),
    onSuccess: (data) => {
      const blockedMessage =
        data.blocked > 0 ? t('repositories.rescanBlocked', { count: data.blocked }) : ''
      const skippedMessage =
        (data.skipped ?? 0) > 0
          ? t('repositories.rescanSkipped', { count: data.skipped })
          : ''

      window.alert(
        t('repositories.rescanResult', {
          blocked: blockedMessage,
          enqueued: data.enqueued,
          skipped: skippedMessage,
          total: data.total,
        }),
      )

      queryClient.invalidateQueries({ queryKey: ['scan-jobs'] })
      queryClient.invalidateQueries({ queryKey: ['scan-jobs-summary'] })
      setTimeout(() => queryClient.invalidateQueries({ queryKey: ['repos'] }), 1500)
    },
  })

  const exposureMutation = useMutation({
    mutationFn: (input: RepoExposureUpdateInput) =>
      updateRepoExposure(input.repoId, {
        exposure_source: 'manual',
        is_internet_exposed: input.isInternetExposed,
        asset_criticality: input.assetCriticality,
        data_sensitivity: input.dataSensitivity,
        environment: input.environment,
      }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['repos'] })
      queryClient.invalidateQueries({ queryKey: ['github-repos'] })
    },
  })

  const handleRescanAll = () => {
    if (repos.length === 0) return
    const scope = selectedOrg
      ? t('repositories.rescanScopeOrg')
      : t('repositories.rescanScopeAll')
    if (!window.confirm(t('repositories.rescanConfirm', { count: repos.length, scope }))) {
      return
    }
    rescanAllMutation.mutate()
  }

  const installableOrgs = orgs.filter((org) => org.github_app_installation_id != null)

  const openBrowse = () => {
    if (installableOrgs.length === 0) return
    const target = installableOrgs.find((org) => org.id === selectedOrg) ?? installableOrgs[0]
    setBrowseOrg(target)
  }

  if (isLoading) return <PageSpinner />

  return (
    <div className="space-y-4">
      {hasActiveScans && (
        <div className="flex items-center justify-between gap-3 rounded-xl border border-blue-200 bg-blue-50 px-4 py-3 text-sm text-blue-900">
          <div className="flex items-center gap-2">
            <Activity className="h-4 w-4" />
            <span>
              {t('repositories.activeScans', {
                pending: scanSummary?.pending ?? 0,
                running: scanSummary?.running ?? 0,
              })}
            </span>
          </div>
          <Link
            to="/scans"
            className="text-xs font-medium text-blue-800 underline hover:text-blue-950"
          >
            {t('repositories.viewScanQueue')}
          </Link>
        </div>
      )}

      {scanFeedback && (
        <div className="flex items-center justify-between gap-3 rounded-xl border border-amber-200 bg-amber-50 px-4 py-3 text-sm text-amber-900">
          <span>{scanFeedback}</span>
          <button
            type="button"
            onClick={() => setScanFeedback(null)}
            className="text-amber-700 hover:text-amber-950"
            title={t('common.close')}
          >
            <X className="h-4 w-4" />
          </button>
        </div>
      )}

      <div className="flex flex-wrap items-center justify-between gap-3">
        {orgs.length > 0 ? (
          <div className="flex flex-wrap items-center gap-3">
            <label className="text-sm font-medium text-gray-600">
              {t('repositories.organization')}
            </label>
            <select
              value={selectedOrg}
              onChange={(event) => setSelectedOrg(event.target.value)}
              className="rounded-lg border border-gray-200 bg-white px-3 py-1.5 text-sm focus:outline-none focus:ring-2 focus:ring-brand-500"
            >
              <option value="">{t('common.all')}</option>
              {orgs.map((org) => (
                <option key={org.id} value={org.id}>
                  {org.github_org_login}
                </option>
              ))}
            </select>

            <label className="text-sm font-medium text-gray-600">{t('repositories.exposure')}</label>
            <select
              value={exposureFilter}
              onChange={(event) =>
                setExposureFilter(event.target.value as 'pending' | 'internet' | 'internal' | '')
              }
              className="rounded-lg border border-gray-200 bg-white px-3 py-1.5 text-sm focus:outline-none focus:ring-2 focus:ring-brand-500"
            >
              <option value="">{t('common.all')}</option>
              <option value="pending">{t('repositories.exposurePending')}</option>
              <option value="internet">{t('common.exposure.internet')}</option>
              <option value="internal">{t('common.exposure.internal')}</option>
            </select>
          </div>
        ) : (
          <div />
        )}

        <div className="flex items-center gap-2">
          <button
            onClick={handleRescanAll}
            disabled={repos.length === 0 || rescanAllMutation.isPending}
            title={t('repositories.rescanAllTitle')}
            className="inline-flex items-center gap-2 rounded-lg border border-gray-200 bg-white px-4 py-2 text-sm font-medium text-gray-700 transition-colors hover:bg-gray-50 disabled:cursor-not-allowed disabled:opacity-40"
          >
            <RefreshCw className={cn('h-4 w-4', rescanAllMutation.isPending && 'animate-spin')} />
            {t('repositories.rescanAll')}
          </button>

          <button
            onClick={openBrowse}
            disabled={installableOrgs.length === 0}
            title={
              installableOrgs.length === 0
                ? t('repositories.browseDisabledNoOrg')
                : t('repositories.browseTitle')
            }
            className="inline-flex items-center gap-2 rounded-lg bg-gray-900 px-4 py-2 text-sm font-medium text-white transition-colors hover:bg-gray-800 disabled:cursor-not-allowed disabled:opacity-40"
          >
            <Github className="h-4 w-4" />
            {t('repositories.browseGithub')}
          </button>
        </div>
      </div>

      {repos.length === 0 ? (
        <div className="rounded-xl border border-gray-200 bg-white">
          <EmptyState
            icon={GitBranch}
            title={t('repositories.emptyTitle')}
            description={t('repositories.emptyDescription')}
            action={
              <a
                href="/settings"
                className="rounded-lg bg-brand-600 px-4 py-2 text-sm font-medium text-white transition-colors hover:bg-brand-700"
              >
                {t('repositories.configureOrg')}
              </a>
            }
          />
        </div>
      ) : (
        <div className="overflow-hidden rounded-xl border border-gray-200 bg-white">
          <div className="flex items-center justify-between border-b border-gray-100 px-6 py-4">
            <h2 className="font-semibold text-gray-900">{t('repositories.count', { count: repos.length })}</h2>
            {isFetching && hasActiveScans && (
              <span className="inline-flex items-center gap-1 text-xs text-gray-500">
                <RefreshCw className="h-3.5 w-3.5 animate-spin" />
                {t('common.updating')}
              </span>
            )}
          </div>
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-gray-100">
                <th className="px-6 py-3 text-left font-medium text-gray-500">
                  {t('repositories.columns.repository')}
                </th>
                <th className="px-6 py-3 text-left font-medium text-gray-500">
                  {t('repositories.columns.branch')}
                </th>
                <th className="px-6 py-3 text-left font-medium text-gray-500">
                  {t('repositories.columns.scanStatus')}
                </th>
                <th className="px-6 py-3 text-left font-medium text-gray-500">
                  {t('repositories.columns.exposure')}
                </th>
                <th className="px-6 py-3 text-left font-medium text-gray-500">
                  {t('repositories.columns.type')}
                </th>
                <th className="px-6 py-3 text-right font-medium text-gray-500">
                  {t('repositories.columns.actions')}
                </th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-50">
              {repos.map((repo) => (
                <RepoRow
                  key={repo.id}
                  repo={repo}
                  onScan={() => scanMutation.mutate(repo.id)}
                  scanning={scanMutation.isPending && scanMutation.variables === repo.id}
                  onSetExposure={(input) =>
                    exposureMutation.mutate({ ...input, repoId: repo.id })
                  }
                  settingExposure={
                    exposureMutation.isPending &&
                    exposureMutation.variables?.repoId === repo.id
                  }
                />
              ))}
            </tbody>
          </table>
        </div>
      )}

      {browseOrg && (
        <BrowseGitHubDialog
          org={browseOrg}
          orgs={installableOrgs}
          onClose={() => setBrowseOrg(null)}
          onSwitchOrg={(nextOrg) => setBrowseOrg(nextOrg)}
          onScanned={() =>
            setTimeout(() => queryClient.invalidateQueries({ queryKey: ['repos'] }), 1500)
          }
        />
      )}
    </div>
  )
}

function BrowseGitHubDialog({
  onClose,
  onScanned,
  onSwitchOrg,
  org,
  orgs,
}: {
  onClose: () => void
  onScanned: () => void
  onSwitchOrg: (org: Org) => void
  org: Org
  orgs: Org[]
}) {
  const { t } = useTranslation()
  const locale = getAppLocale()
  const [search, setSearch] = useState('')
  const [selected, setSelected] = useState<Set<number>>(new Set())
  const [feedback, setFeedback] = useState<string | null>(null)
  const queryClient = useQueryClient()
  const sentinelRef = useRef<HTMLDivElement | null>(null)

  const {
    data,
    error,
    fetchNextPage,
    hasNextPage,
    isError,
    isFetchingNextPage,
    isLoading,
    isRefetching,
    refetch,
  } = useInfiniteQuery({
    queryKey: ['github-repos', org.id],
    queryFn: ({ pageParam = 1 }) => listGitHubRepos(org.id, pageParam as number, BROWSE_PER_PAGE),
    initialPageParam: 1,
    getNextPageParam: (lastPage) => (lastPage.next_page > 0 ? lastPage.next_page : undefined),
    staleTime: BROWSE_STALE_MS,
    refetchOnWindowFocus: false,
  })

  const loadedRepos: GitHubRepo[] = useMemo(
    () => data?.pages.flatMap((page) => page.repos) ?? [],
    [data],
  )

  const filtered = useMemo(() => {
    const query = search.trim().toLowerCase()
    if (!query) return loadedRepos
    return loadedRepos.filter(
      (repo) =>
        repo.full_name.toLowerCase().includes(query) ||
        repo.description.toLowerCase().includes(query),
    )
  }, [loadedRepos, search])

  useEffect(() => {
    setSelected(new Set())
    setFeedback(null)
  }, [org.id])

  useEffect(() => {
    if (!sentinelRef.current || !hasNextPage) return
    const observer = new IntersectionObserver(
      (entries) => {
        if (entries[0]?.isIntersecting && !isFetchingNextPage) {
          fetchNextPage()
        }
      },
      { rootMargin: '200px' },
    )
    observer.observe(sentinelRef.current)
    return () => observer.disconnect()
  }, [fetchNextPage, hasNextPage, isFetchingNextPage, loadedRepos.length])

  const batchMutation = useMutation({
    mutationFn: (repos: GitHubRepo[]) =>
      scanGitHubReposBatch(
        org.id,
        repos.map((repo) => ({
          default_branch: repo.default_branch,
          full_name: repo.full_name,
          github_repo_id: repo.github_repo_id,
        })),
      ),
    onSuccess: (response) => {
      setSelected(new Set())
      onScanned()
      queryClient.invalidateQueries({ queryKey: ['github-repos', org.id] })

      const notes: string[] = []
      if (response.failed > 0) {
        notes.push(t('repositories.browse.batchFailed', { count: response.failed }))
      }
      if (response.blocked > 0) {
        notes.push(t('repositories.browse.batchBlocked', { count: response.blocked }))
      }
      if ((response.skipped ?? 0) > 0) {
        notes.push(t('repositories.browse.batchSkipped', { count: response.skipped }))
      }

      const suffix = notes.length > 0 ? ` (${notes.join(', ')})` : ''
      setFeedback(
        t('repositories.browse.batchEnqueued', {
          count: response.enqueued,
          suffix,
        }),
      )
    },
    onError: (error) => {
      setFeedback(getScanApiErrorMessage(error) ?? t('repositories.scanEnqueueError'))
    },
  })

  const syncMutation = useMutation({
    mutationFn: () => syncOrgRepos(org.id),
    onSuccess: (response) => {
      queryClient.invalidateQueries({ queryKey: ['github-repos', org.id] })
      onScanned()
      setFeedback(
        t('repositories.browse.syncResult', {
          imported: response.imported,
          total: response.total_from_github,
          updated: response.updated,
        }),
      )
    },
    onError: () => setFeedback(t('repositories.browse.syncError')),
  })

  const allVisibleIds = useMemo(() => filtered.map((repo) => repo.github_repo_id), [filtered])
  const allVisibleSelected =
    allVisibleIds.length > 0 && allVisibleIds.every((id) => selected.has(id))

  const toggleAllVisible = () => {
    const next = new Set(selected)
    if (allVisibleSelected) {
      allVisibleIds.forEach((id) => next.delete(id))
    } else {
      allVisibleIds.forEach((id) => next.add(id))
    }
    setSelected(next)
  }

  const toggleOne = (id: number) => {
    const next = new Set(selected)
    if (next.has(id)) {
      next.delete(id)
    } else {
      next.add(id)
    }
    setSelected(next)
  }

  const handleScanSelected = () => {
    if (selected.size === 0) return
    if (selected.size > SCAN_BATCH_MAX) {
      setFeedback(t('repositories.browse.batchLimit', { max: SCAN_BATCH_MAX }))
      return
    }
    const targets = loadedRepos.filter((repo) => selected.has(repo.github_repo_id))
    batchMutation.mutate(targets)
  }

  const apiErrorMessage =
    (error as { response?: { data?: { error?: string } } })?.response?.data?.error ??
    t('repositories.browse.loadError')

  return (
    <div
      className="fixed inset-0 z-50 flex items-start justify-center bg-black/40 p-4 sm:p-10"
      onClick={onClose}
    >
      <div
        className="flex max-h-[85vh] w-full max-w-4xl flex-col overflow-hidden rounded-2xl bg-white shadow-xl"
        onClick={(event) => event.stopPropagation()}
      >
        <div className="flex items-center justify-between gap-3 border-b border-gray-100 px-6 py-4">
          <div className="flex min-w-0 items-center gap-3">
            <Github className="h-5 w-5 flex-shrink-0 text-gray-700" />
            <div className="min-w-0">
              <h2 className="truncate font-semibold text-gray-900">
                {t('repositories.browse.title', { org: org.github_org_login })}
              </h2>
              <p className="text-xs text-gray-500">{t('repositories.browse.subtitle')}</p>
            </div>
          </div>

          <div className="flex items-center gap-2">
            {orgs.length > 1 && (
              <select
                value={org.id}
                onChange={(event) => {
                  const nextOrg = orgs.find((candidate) => candidate.id === event.target.value)
                  if (nextOrg) onSwitchOrg(nextOrg)
                }}
                className="rounded-lg border border-gray-200 bg-white px-3 py-1.5 text-sm focus:outline-none focus:ring-2 focus:ring-brand-500"
              >
                {orgs.map((candidate) => (
                  <option key={candidate.id} value={candidate.id}>
                    {candidate.github_org_login}
                  </option>
                ))}
              </select>
            )}

            <button
              onClick={() => syncMutation.mutate()}
              disabled={syncMutation.isPending}
              title={t('repositories.browse.syncTitle')}
              className="inline-flex items-center gap-1.5 rounded-lg border border-gray-200 px-3 py-1.5 text-sm text-gray-700 transition-colors hover:bg-gray-50 disabled:opacity-50"
            >
              {syncMutation.isPending ? (
                <>
                  <Loader className="h-3.5 w-3.5 animate-spin" />
                  {t('repositories.browse.syncing')}
                </>
              ) : (
                <>
                  <Download className="h-3.5 w-3.5" />
                  {t('repositories.browse.syncAll')}
                </>
              )}
            </button>

            <button
              onClick={onClose}
              className="rounded-lg p-2 text-gray-400 hover:bg-gray-50 hover:text-gray-600"
              title={t('common.close')}
            >
              <X className="h-4 w-4" />
            </button>
          </div>
        </div>

        <div className="border-b border-gray-100 px-6 py-3">
          <div className="relative">
            <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-gray-400" />
            <input
              type="text"
              value={search}
              onChange={(event) => setSearch(event.target.value)}
              placeholder={t('repositories.browse.filterPlaceholder')}
              className="w-full rounded-lg border border-gray-200 bg-white py-2 pl-9 pr-3 text-sm focus:outline-none focus:ring-2 focus:ring-brand-500"
            />
          </div>
        </div>

        {feedback && (
          <div className="flex items-center justify-between border-b border-blue-100 bg-blue-50 px-6 py-2 text-xs text-blue-900">
            <span>{feedback}</span>
            <button
              onClick={() => setFeedback(null)}
              className="text-blue-700 hover:text-blue-900"
              title={t('common.close')}
            >
              <X className="h-3.5 w-3.5" />
            </button>
          </div>
        )}

        <div className="flex-1 overflow-y-auto">
          {isLoading ? (
            <div className="p-10">
              <PageSpinner />
            </div>
          ) : isError ? (
            <div className="space-y-3 p-8 text-center">
              <AlertCircle className="mx-auto h-8 w-8 text-red-400" />
              <p className="text-sm text-red-600">{apiErrorMessage}</p>
              <button
                onClick={() => refetch()}
                className="rounded-lg border border-gray-200 px-3 py-1.5 text-sm text-gray-700 transition-colors hover:bg-gray-50"
              >
                {t('common.tryAgain')}
              </button>
            </div>
          ) : filtered.length === 0 ? (
            <div className="p-8 text-center text-sm text-gray-500">
              {search
                ? t('repositories.browse.noFilterMatch')
                : t('repositories.browse.noReposInOrg')}
            </div>
          ) : (
            <table className="w-full text-sm">
              <thead className="sticky top-0 border-b border-gray-100 bg-white">
                <tr>
                  <th className="w-8 py-2.5 pl-6 pr-2">
                    <input
                      type="checkbox"
                      checked={allVisibleSelected}
                      onChange={toggleAllVisible}
                      title={t('repositories.browse.selectAllVisible')}
                      className="h-4 w-4 rounded border-gray-300 text-brand-600 focus:ring-brand-500"
                    />
                  </th>
                  <th className="px-2 py-2.5 text-left font-medium text-gray-500">
                    {t('repositories.columns.repository')}
                  </th>
                  <th className="px-6 py-2.5 text-left font-medium text-gray-500">
                    {t('repositories.browse.language')}
                  </th>
                  <th className="px-6 py-2.5 text-left font-medium text-gray-500">
                    {t('repositories.browse.status')}
                  </th>
                  <th className="px-6 py-2.5 text-right font-medium text-gray-500">
                    {t('repositories.browse.action')}
                  </th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-50">
                {filtered.map((repo) => (
                  <GitHubRepoRow
                    key={repo.github_repo_id}
                    repo={repo}
                    checked={selected.has(repo.github_repo_id)}
                    onToggle={() => toggleOne(repo.github_repo_id)}
                    onScan={() => batchMutation.mutate([repo])}
                    scanning={
                      batchMutation.isPending &&
                      batchMutation.variables?.some(
                        (selectedRepo) => selectedRepo.github_repo_id === repo.github_repo_id,
                      ) === true
                    }
                  />
                ))}
              </tbody>
            </table>
          )}

          {hasNextPage && (
            <div ref={sentinelRef} className="px-6 py-4 text-center text-xs text-gray-400">
              {isFetchingNextPage ? (
                <span className="inline-flex items-center gap-2">
                  <Loader className="h-3.5 w-3.5 animate-spin" />
                  {t('repositories.browse.loadingMore')}
                </span>
              ) : (
                <button onClick={() => fetchNextPage()} className="text-gray-500 hover:text-gray-800">
                  {t('repositories.browse.loadMore')}
                </button>
              )}
            </div>
          )}
        </div>

        <div className="flex items-center justify-between gap-3 border-t border-gray-100 px-6 py-3">
          <div className="text-xs text-gray-500">
            {t('repositories.browse.loadedFooter', {
              count: filtered.length,
              morePages: hasNextPage ? t('common.morePages') : '',
              ofLoaded: search ? t('common.ofLoaded', { total: loadedRepos.length }) : '',
              updating:
                isRefetching && !isFetchingNextPage ? t('common.updatingInline') : '',
            })}
          </div>

          <div className="flex items-center gap-2">
            {selected.size > 0 && (
              <>
                <span className="text-xs text-gray-700">
                  {t('repositories.browse.selected', { count: selected.size })}
                </span>
                <button
                  onClick={() => setSelected(new Set())}
                  className="text-xs text-gray-500 hover:text-gray-700"
                >
                  {t('repositories.browse.clearSelection')}
                </button>
                <button
                  onClick={handleScanSelected}
                  disabled={batchMutation.isPending}
                  className="inline-flex items-center gap-1.5 rounded-lg bg-brand-600 px-3 py-1.5 text-xs font-medium text-white transition-colors hover:bg-brand-700 disabled:opacity-50"
                >
                  {batchMutation.isPending ? (
                    <>
                      <Loader className="h-3.5 w-3.5 animate-spin" />
                      {t('repositories.browse.queueingSelected', { count: selected.size })}
                    </>
                  ) : (
                    <>
                      <Play className="h-3.5 w-3.5" />
                      {t('repositories.browse.scanSelected')}
                    </>
                  )}
                </button>
              </>
            )}

            <button
              onClick={() => refetch()}
              className="inline-flex items-center gap-1 text-xs text-gray-600 hover:text-gray-900"
            >
              <RefreshCw className="h-3.5 w-3.5" />
              {t('common.refresh')}
            </button>
          </div>
        </div>
      </div>
    </div>
  )
}

function GitHubRepoRow({
  checked,
  onScan,
  onToggle,
  repo,
  scanning,
}: {
  checked: boolean
  onScan: () => void
  onToggle: () => void
  repo: GitHubRepo
  scanning: boolean
}) {
  const { t } = useTranslation()
  const locale = getAppLocale()
  const isScanBlocked = repo.is_tracked && repo.is_internet_exposed == null
  const isScanActive = isRepoScanActive(repo.latest_scan_status)
  const scanDisabled = scanning || isScanBlocked || isScanActive

  return (
    <tr className={cn('transition-colors', checked ? 'bg-brand-50/40' : 'hover:bg-gray-50')}>
      <td className="w-8 py-3 pl-6 pr-2">
        <input
          type="checkbox"
          checked={checked}
          onChange={onToggle}
          className="h-4 w-4 rounded border-gray-300 text-brand-600 focus:ring-brand-500"
        />
      </td>
      <td className="px-2 py-3">
        <div className="flex items-start gap-2">
          <GitBranch className="mt-0.5 h-4 w-4 flex-shrink-0 text-gray-400" />
          <div className="min-w-0">
            <div className="flex items-center gap-2">
              <span className="truncate font-medium text-gray-900">{repo.full_name}</span>
              {repo.private && (
                <Lock className="h-3 w-3 text-gray-400" aria-label={t('repositories.browse.private')} />
              )}
            </div>
            {repo.description && (
              <p className="mt-0.5 truncate text-xs text-gray-500">{repo.description}</p>
            )}
          </div>
        </div>
      </td>
      <td className="px-6 py-3 text-xs text-gray-500">{repo.language || '—'}</td>
      <td className="px-6 py-3">
        {repo.is_tracked ? (
          <div className="flex flex-wrap items-center gap-1.5">
            <span className="inline-flex items-center gap-1 rounded-full bg-blue-50 px-2 py-0.5 text-xs text-blue-700 ring-1 ring-blue-200">
              <CheckCircle className="h-3 w-3" />
              {repo.last_scanned_at
                ? t('repositories.browse.scannedAt', {
                    date: formatDateTime(repo.last_scanned_at, locale),
                  })
                : t('repositories.browse.tracked')}
            </span>
            <ExposureBadge isInternetExposed={repo.is_internet_exposed} />
          </div>
        ) : (
          <span className="text-xs text-gray-400">{t('repositories.browse.new')}</span>
        )}
      </td>
      <td className="px-6 py-3 text-right">
        <button
          onClick={onScan}
          disabled={scanDisabled}
          title={
            isScanBlocked
              ? t('repositories.browse.scanBlockedClassify')
              : isScanActive
                ? t('repositories.scanAlreadyActive')
                : undefined
          }
          className={cn(
            'inline-flex items-center gap-1.5 rounded-lg px-3 py-1.5 text-xs font-medium transition-colors',
            scanDisabled
              ? 'cursor-not-allowed bg-gray-100 text-gray-400'
              : 'bg-brand-50 text-brand-700 hover:bg-brand-100',
          )}
        >
          {scanning ? (
            <>
              <Loader className="h-3.5 w-3.5 animate-spin" />
              {t('repositories.scanning')}
            </>
          ) : isScanActive ? (
            <>
              <Loader className="h-3.5 w-3.5 animate-spin" />
              {t('repositories.scanRunning')}
            </>
          ) : (
            <>
              <Play className="h-3.5 w-3.5" />
              {t('repositories.scan')}
            </>
          )}
        </button>
      </td>
    </tr>
  )
}

function RepoRow({
  onScan,
  onSetExposure,
  repo,
  scanning,
  settingExposure,
}: {
  onScan: () => void
  onSetExposure: (input: Omit<RepoExposureUpdateInput, 'repoId'>) => void
  repo: Repo
  scanning: boolean
  settingExposure: boolean
}) {
  const { t } = useTranslation()
  const navigate = useNavigate()
  const hasBeenScanned = Boolean(repo.last_scanned_at)
  const isScanBlocked = repo.is_internet_exposed == null
  const isScanActive = isRepoScanActive(repo.latest_scan_status)
  const scanDisabled = scanning || isScanBlocked || isScanActive

  const openFindings = () => {
    if (!hasBeenScanned) return
    const params = new URLSearchParams({
      repo_id: repo.id,
      repo_name: repo.full_name,
    })
    navigate(`/triage?${params.toString()}`)
  }

  return (
    <tr
      className={cn(
        'transition-colors',
        hasBeenScanned ? 'cursor-pointer hover:bg-brand-50/40' : 'hover:bg-gray-50',
      )}
      onClick={openFindings}
      title={hasBeenScanned ? t('repositories.viewFindings') : undefined}
    >
      <td className="px-6 py-3">
        <div className="flex items-center gap-2">
          <GitBranch className="h-4 w-4 flex-shrink-0 text-gray-400" />
          <span className="font-medium text-gray-900">{repo.full_name}</span>
        </div>
      </td>
      <td className="px-6 py-3 text-gray-500">{repo.default_branch}</td>
      <td className="px-6 py-3">
        <ScanStatusBadge status={repo.latest_scan_status} lastScannedAt={repo.last_scanned_at} />
      </td>
      <td
        className="px-6 py-3"
        onClick={(event) => event.stopPropagation()}
      >
        <ExposureControls
          isInternetExposed={repo.is_internet_exposed}
          assetCriticality={repo.asset_criticality}
          dataSensitivity={repo.data_sensitivity}
          environment={repo.environment}
          onSetExposure={onSetExposure}
          settingExposure={settingExposure}
        />
      </td>
      <td className="px-6 py-3">
        {repo.is_monorepo && (
          <span className="inline-flex items-center rounded-full bg-purple-50 px-2 py-0.5 text-xs font-medium text-purple-700 ring-1 ring-purple-200">
            {t('repositories.monorepo')}
          </span>
        )}
      </td>
      <td className="px-6 py-3 text-right">
        <button
          onClick={(event) => {
            event.stopPropagation()
            onScan()
          }}
          disabled={scanDisabled}
          title={
            isScanBlocked
              ? t('repositories.scanBlockedExposure')
              : isScanActive
                ? t('repositories.scanAlreadyActive')
                : undefined
          }
          className={cn(
            'inline-flex items-center gap-1.5 rounded-lg px-3 py-1.5 text-xs font-medium transition-colors',
            scanDisabled
              ? 'cursor-not-allowed bg-gray-100 text-gray-400'
              : 'bg-brand-50 text-brand-700 hover:bg-brand-100',
          )}
        >
          {scanning ? (
            <>
              <Loader className="h-3.5 w-3.5 animate-spin" />
              {t('repositories.scanQueued')}
            </>
          ) : isScanActive ? (
            <>
              <Loader className="h-3.5 w-3.5 animate-spin" />
              {t('repositories.scanRunning')}
            </>
          ) : (
            <>
              <Play className="h-3.5 w-3.5" />
              {t('repositories.scan')}
            </>
          )}
        </button>
      </td>
    </tr>
  )
}

function ExposureControls({
  isInternetExposed,
  assetCriticality,
  dataSensitivity,
  environment,
  onSetExposure,
  settingExposure,
}: {
  isInternetExposed: boolean | null | undefined
  assetCriticality: Repo['asset_criticality']
  dataSensitivity: Repo['data_sensitivity']
  environment: Repo['environment']
  onSetExposure: (input: Omit<RepoExposureUpdateInput, 'repoId'>) => void
  settingExposure: boolean
}) {
  const { t } = useTranslation()
  const canEditContext = isInternetExposed != null
  const assetLabelMap: Record<Repo['asset_criticality'], string> = {
    low: t('repositories.context.criticalityLow'),
    medium: t('repositories.context.criticalityMedium'),
    high: t('repositories.context.criticalityHigh'),
    critical: t('repositories.context.criticalityCritical'),
  }
  const sensitivityLabelMap: Record<Repo['data_sensitivity'], string> = {
    public: t('repositories.context.sensitivityPublic'),
    internal: t('repositories.context.sensitivityInternal'),
    confidential: t('repositories.context.sensitivityConfidential'),
    restricted: t('repositories.context.sensitivityRestricted'),
  }
  const environmentLabelMap: Record<Repo['environment'], string> = {
    dev: t('repositories.context.environmentDev'),
    staging: t('repositories.context.environmentStaging'),
    prod: t('repositories.context.environmentProd'),
  }

  const saveExposure = (nextExposure: boolean) => {
    onSetExposure({
      isInternetExposed: nextExposure,
      assetCriticality,
      dataSensitivity,
      environment,
    })
  }

  const saveContext = (next: Partial<Pick<RepoExposureUpdateInput, 'assetCriticality' | 'dataSensitivity' | 'environment'>>) => {
    if (!canEditContext) return
    const currentExposure = isInternetExposed as boolean
    onSetExposure({
      isInternetExposed: currentExposure,
      assetCriticality: next.assetCriticality ?? assetCriticality,
      dataSensitivity: next.dataSensitivity ?? dataSensitivity,
      environment: next.environment ?? environment,
    })
  }

  return (
    <div className="space-y-2">
      <div className="flex items-center gap-2">
        <ExposureBadge isInternetExposed={isInternetExposed} />
        <div
          className="inline-flex items-center gap-1"
          role="group"
          aria-label={t('common.exposure.classification')}
        >
          <button
            type="button"
            onClick={() => saveExposure(true)}
            disabled={settingExposure || isInternetExposed === true}
            title={t('common.exposure.markInternet')}
            className={cn(
              'rounded-md px-2 py-1 text-[11px] font-medium transition-colors disabled:opacity-50',
              isInternetExposed === true
                ? 'cursor-default bg-orange-100 text-orange-800 ring-1 ring-orange-300'
                : 'bg-orange-50 text-orange-700 hover:bg-orange-100',
            )}
          >
            {t('common.exposure.internet')}
          </button>
          <button
            type="button"
            onClick={() => saveExposure(false)}
            disabled={settingExposure || isInternetExposed === false}
            title={t('common.exposure.markInternal')}
            className={cn(
              'rounded-md px-2 py-1 text-[11px] font-medium transition-colors disabled:opacity-50',
              isInternetExposed === false
                ? 'cursor-default bg-emerald-100 text-emerald-800 ring-1 ring-emerald-300'
                : 'bg-gray-100 text-gray-700 hover:bg-gray-200',
            )}
          >
            {t('common.exposure.internal')}
          </button>
        </div>
      </div>

      <div className="grid grid-cols-3 gap-1.5">
        <select
          value={assetCriticality}
          disabled={settingExposure || !canEditContext}
          onChange={(event) =>
            saveContext({ assetCriticality: event.target.value as Repo['asset_criticality'] })
          }
          title={
            canEditContext
              ? t('repositories.context.assetCriticality')
              : t('repositories.context.setExposureFirst')
          }
          className="rounded border border-gray-200 bg-white px-1.5 py-1 text-[11px] text-gray-700 disabled:opacity-50"
        >
          <option value="low">{t('repositories.context.criticalityLow')}</option>
          <option value="medium">{t('repositories.context.criticalityMedium')}</option>
          <option value="high">{t('repositories.context.criticalityHigh')}</option>
          <option value="critical">{t('repositories.context.criticalityCritical')}</option>
        </select>

        <select
          value={dataSensitivity}
          disabled={settingExposure || !canEditContext}
          onChange={(event) =>
            saveContext({ dataSensitivity: event.target.value as Repo['data_sensitivity'] })
          }
          title={
            canEditContext
              ? t('repositories.context.dataSensitivity')
              : t('repositories.context.setExposureFirst')
          }
          className="rounded border border-gray-200 bg-white px-1.5 py-1 text-[11px] text-gray-700 disabled:opacity-50"
        >
          <option value="public">{t('repositories.context.sensitivityPublic')}</option>
          <option value="internal">{t('repositories.context.sensitivityInternal')}</option>
          <option value="confidential">{t('repositories.context.sensitivityConfidential')}</option>
          <option value="restricted">{t('repositories.context.sensitivityRestricted')}</option>
        </select>

        <select
          value={environment}
          disabled={settingExposure || !canEditContext}
          onChange={(event) =>
            saveContext({ environment: event.target.value as Repo['environment'] })
          }
          title={
            canEditContext
              ? t('repositories.context.environment')
              : t('repositories.context.setExposureFirst')
          }
          className="rounded border border-gray-200 bg-white px-1.5 py-1 text-[11px] text-gray-700 disabled:opacity-50"
        >
          <option value="dev">{t('repositories.context.environmentDev')}</option>
          <option value="staging">{t('repositories.context.environmentStaging')}</option>
          <option value="prod">{t('repositories.context.environmentProd')}</option>
        </select>
      </div>

      <div className="flex flex-wrap items-center gap-1">
        <span
          className="rounded-full bg-slate-100 px-2 py-0.5 text-[10px] font-medium text-slate-700 ring-1 ring-slate-200"
          title={t('repositories.context.assetCriticality')}
        >
          {assetLabelMap[assetCriticality]}
        </span>
        <span
          className="rounded-full bg-slate-100 px-2 py-0.5 text-[10px] font-medium text-slate-700 ring-1 ring-slate-200"
          title={t('repositories.context.dataSensitivity')}
        >
          {sensitivityLabelMap[dataSensitivity]}
        </span>
        <span
          className="rounded-full bg-slate-100 px-2 py-0.5 text-[10px] font-medium text-slate-700 ring-1 ring-slate-200"
          title={t('repositories.context.environment')}
        >
          {environmentLabelMap[environment]}
        </span>
      </div>
    </div>
  )
}

function ExposureBadge({
  isInternetExposed,
}: {
  isInternetExposed: boolean | null | undefined
}) {
  const { t } = useTranslation()

  if (isInternetExposed == null) {
    return (
      <span className="inline-flex items-center gap-1 rounded-full bg-amber-50 px-2 py-0.5 text-xs font-medium text-amber-700 ring-1 ring-amber-200">
        <ShieldAlert className="h-3 w-3" />
        {t('common.exposure.unclassified')}
      </span>
    )
  }

  if (isInternetExposed) {
    return (
      <span className="inline-flex items-center rounded-full bg-red-50 px-2 py-0.5 text-xs font-medium text-red-700 ring-1 ring-red-200">
        {t('common.exposure.internet')}
      </span>
    )
  }

  return (
    <span className="inline-flex items-center rounded-full bg-emerald-50 px-2 py-0.5 text-xs font-medium text-emerald-700 ring-1 ring-emerald-200">
      {t('common.exposure.internal')}
    </span>
  )
}
