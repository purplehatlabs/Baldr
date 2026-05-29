import { useQuery } from '@tanstack/react-query'
import { Link } from 'react-router-dom'
import type { ReactNode } from 'react'
import { useTranslation } from 'react-i18next'
import {
  Bar,
  BarChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts'
import {
  Activity,
  AlertTriangle,
  ChevronRight,
  FolderKanban,
  GitBranch,
  ShieldCheck,
  TrendingDown,
  TrendingUp,
  Users,
} from 'lucide-react'
import {
  getMetricsOverview,
  getRiskByRepo,
  getRiskByTeam,
  getRiskTrend,
  type RiskTrendPoint,
} from '@/api/metrics'
import { listTopRisks } from '@/api/findings'
import { PageSpinner } from '@/components/shared/Spinner'
import { EmptyState } from '@/components/shared/EmptyState'
import { SeverityBadge } from '@/components/shared/SeverityBadge'
import { cn } from '@/lib/utils'

export default function OverviewPage() {
  const { t } = useTranslation()
  const { data: overview, isLoading: isLoadingOverview } = useQuery({
    queryKey: ['metrics', 'overview'],
    queryFn: getMetricsOverview,
    refetchInterval: 30_000,
  })
  const { data: riskTrendData, isLoading: isLoadingTrend } = useQuery({
    queryKey: ['metrics', 'risk-trend'],
    queryFn: () => getRiskTrend(30),
    refetchInterval: 30_000,
  })
  const { data: riskByRepo = [] } = useQuery({
    queryKey: ['metrics', 'risk-by-repo'],
    queryFn: () => getRiskByRepo(10),
    refetchInterval: 30_000,
  })
  const { data: riskByTeam = [] } = useQuery({
    queryKey: ['metrics', 'risk-by-team'],
    queryFn: () => getRiskByTeam(10),
    refetchInterval: 30_000,
  })
  const { data: topRisks = [] } = useQuery({
    queryKey: ['findings', 'top-risks'],
    queryFn: () => listTopRisks(10),
    refetchInterval: 30_000,
  })

  if (isLoadingOverview || !overview) return <PageSpinner />

  const trend = riskTrendData?.trend ?? []

  return (
    <div className="space-y-6">
      {/* Executive KPIs */}
      <section>
        <SectionHeader
          title={t('overview.globalPosture.title')}
          description={t('overview.globalPosture.description')}
        />
        <div className="grid gap-4 grid-cols-1 sm:grid-cols-2 xl:grid-cols-3 mt-4">
          <KpiCard
            label={t('overview.kpi.openCritical')}
            value={overview.open_critical}
            icon={AlertTriangle}
            href="/triage?severity=critical&status=open"
            accent="danger"
          />
          <KpiCard
            label={t('overview.kpi.openHigh')}
            value={overview.open_high}
            icon={Activity}
            href="/triage?severity=high&status=open"
            accent="warning"
          />
          <KpiCard
            label={t('overview.kpi.slaBreachRate')}
            value={`${(overview.sla_breach_rate * 100).toFixed(1)}%`}
            icon={AlertTriangle}
            href="/triage?sla_breached=true&status=open"
            accent="danger"
          />
          <KpiCard
            label={t('overview.kpi.criticalWithoutOwner')}
            value={overview.critical_without_owner}
            icon={Users}
            href="/triage?severity=critical&status=open"
          />
          <KpiCard
            label={t('overview.kpi.mttrHighPlus')}
            value={overview.mttr_high_plus_hours.toFixed(1)}
            icon={FolderKanban}
          />
          <KpiCard
            label={t('overview.kpi.scanCoverage')}
            value={`${(overview.scan_coverage_rate * 100).toFixed(1)}%`}
            icon={ShieldCheck}
            href="/repositories"
          />
        </div>
      </section>

      {/* Top risk repos + teams */}
      <div className="grid gap-4 grid-cols-1 lg:grid-cols-2">
        <RiskTableSection
          title={t('overview.topRepos.title')}
          description={t('overview.topRepos.description')}
          icon={GitBranch}
          emptyTitle={t('overview.topRepos.emptyTitle')}
          emptyDescription={t('overview.topRepos.emptyDescription')}
          viewAllHref="/projects"
          viewAllLabel={t('overview.topRepos.viewAll')}
          items={riskByRepo}
          renderRow={(repo) => (
            <Link
              key={repo.repo_id}
              to={`/triage?repo_id=${repo.repo_id}&repo_name=${encodeURIComponent(repo.repo_full_name)}&status=open`}
              className="flex items-center justify-between gap-3 py-3 hover:bg-gray-50 -mx-2 px-2 rounded-lg transition-colors group"
            >
              <div className="min-w-0">
                <p className="font-medium text-gray-900 truncate text-sm">{repo.repo_full_name}</p>
                <div className="flex items-center gap-2 mt-0.5 flex-wrap">
                  {repo.open_critical > 0 && (
                    <span className="text-xs text-red-700 font-medium">{t('overview.topRepos.crit', { count: repo.open_critical })}</span>
                  )}
                  {repo.open_high > 0 && (
                    <span className="text-xs text-orange-700">{t('overview.topRepos.high', { count: repo.open_high })}</span>
                  )}
                  {repo.sla_breach_count > 0 && (
                    <span className="text-xs text-red-600">{t('overview.topRepos.sla', { count: repo.sla_breach_count })}</span>
                  )}
                  {repo.reachable_count > 0 && (
                    <span className="text-xs text-gray-500">{t('overview.topRepos.reachable', { count: repo.reachable_count })}</span>
                  )}
                  {repo.is_internet_exposed === true && (
                    <span className="text-xs text-red-600 bg-red-50 px-1.5 py-0.5 rounded">{t('overview.topRepos.internet')}</span>
                  )}
                  {repo.is_internet_exposed == null && (
                    <span className="text-xs text-amber-600 bg-amber-50 px-1.5 py-0.5 rounded">{t('overview.topRepos.unclassified')}</span>
                  )}
                </div>
              </div>
              <div className="flex items-center gap-2 shrink-0">
                <span className="text-lg font-bold text-gray-900">{repo.max_risk_score.toFixed(0)}</span>
                <ChevronRight className="w-4 h-4 text-gray-300 group-hover:text-gray-500" />
              </div>
            </Link>
          )}
        />

        <RiskTableSection
          title={t('overview.topTeams.title')}
          description={t('overview.topTeams.description')}
          icon={Users}
          emptyTitle={t('overview.topTeams.emptyTitle')}
          emptyDescription={t('overview.topTeams.emptyDescription')}
          viewAllHref="/teams"
          viewAllLabel={t('overview.topTeams.viewAll')}
          items={riskByTeam}
          renderRow={(team) => (
            <Link
              key={team.team_id}
              to={`/triage?team_id=${team.team_id}&status=open`}
              className="flex items-center justify-between gap-3 py-3 hover:bg-gray-50 -mx-2 px-2 rounded-lg transition-colors group"
            >
              <div className="min-w-0">
                <p className="font-medium text-gray-900 truncate text-sm">{team.display_name}</p>
                <p className="text-xs text-gray-500">@{team.team_slug}</p>
                <div className="flex items-center gap-2 mt-0.5">
                  {team.open_critical > 0 && (
                    <span className="text-xs text-red-700 font-medium">{t('overview.topRepos.crit', { count: team.open_critical })}</span>
                  )}
                  {team.open_high > 0 && (
                    <span className="text-xs text-orange-700">{t('overview.topRepos.high', { count: team.open_high })}</span>
                  )}
                  {team.sla_breach_count > 0 && (
                    <span className="text-xs text-red-600">{t('overview.topRepos.sla', { count: team.sla_breach_count })}</span>
                  )}
                </div>
              </div>
              <div className="flex items-center gap-2 shrink-0 text-right">
                <div>
                  <p className="text-lg font-bold text-gray-900">{team.max_risk_score.toFixed(0)}</p>
                  {team.sla_breach_rate > 0 && (
                    <p className="text-xs text-red-600">{t('overview.topTeams.slaRate', { rate: (team.sla_breach_rate * 100).toFixed(0) })}</p>
                  )}
                </div>
                <ChevronRight className="w-4 h-4 text-gray-300 group-hover:text-gray-500" />
              </div>
            </Link>
          )}
        />
      </div>

      {/* Top risks (operational) */}
      <section className="bg-white rounded-xl border border-gray-200 p-6">
        <div className="mb-4 flex items-center justify-between gap-3">
          <SectionHeader
            title={t('overview.topRisks.title')}
            description={t('overview.topRisks.description')}
          />
          <Link
            to="/triage?reachability=reachable&status=open"
            className="text-sm text-brand-600 hover:text-brand-700 font-medium shrink-0"
          >
            {t('overview.topRisks.viewTriage')}
          </Link>
        </div>

        {topRisks.length === 0 ? (
          <EmptyState
            icon={ShieldCheck}
            title={t('overview.topRisks.emptyTitle')}
            description={t('overview.topRisks.emptyDescription')}
          />
        ) : (
          <div className="divide-y divide-gray-100">
            {topRisks.map((finding) => (
              <Link
                key={finding.id}
                to="/triage?status=open&sort=risk_score&order=desc&reachability=reachable"
                className="py-3 flex items-center justify-between gap-4 hover:bg-gray-50 -mx-2 px-2 rounded-lg transition-colors"
              >
                <div className="min-w-0">
                  <div className="flex items-center gap-2 flex-wrap">
                    <SeverityBadge severity={finding.severity} size="sm" />
                    <span className="font-medium text-gray-900 truncate">{finding.package_name}</span>
                    <span className="text-xs text-gray-400">@{finding.package_version}</span>
                  </div>
                  <p className="text-xs text-gray-500 truncate mt-1">
                    {finding.repo_full_name} · {finding.reachability_status ?? 'unknown'}
                  </p>
                </div>
                <div className="text-right shrink-0">
                  <p className="text-lg font-bold text-gray-900">{finding.risk_score?.toFixed(0) ?? '—'}</p>
                  <p className="text-xs text-gray-500 uppercase">{finding.risk_tier ?? '—'}</p>
                </div>
              </Link>
            ))}
          </div>
        )}
      </section>

      <RemediationTrendSection trend={trend} loading={isLoadingTrend} />
    </div>
  )
}

function RemediationTrendSection({
  trend,
  loading,
}: {
  trend: RiskTrendPoint[]
  loading: boolean
}) {
  const { t } = useTranslation()
  const chartDays = trend.slice(-14)
  const totalNew = trend.reduce((sum, point) => sum + point.new_findings, 0)
  const totalFixed = trend.reduce((sum, point) => sum + point.fixed_findings, 0)
  const net = totalFixed - totalNew

  const snapshotDays = trend.filter((point) => point.open_critical > 0 || point.open_high > 0)
  const hasSnapshotTrend = snapshotDays.length >= 2
  const firstSnapshot = snapshotDays[0]
  const lastSnapshot = snapshotDays[snapshotDays.length - 1]
  const backlogDelta =
    hasSnapshotTrend && firstSnapshot && lastSnapshot
      ? lastSnapshot.open_critical +
        lastSnapshot.open_high -
        (firstSnapshot.open_critical + firstSnapshot.open_high)
      : null

  const chartData = chartDays.map((point) => ({
    label: point.date.slice(5),
    novos: point.new_findings,
    corrigidos: point.fixed_findings,
  }))

  const hasActivity = totalNew > 0 || totalFixed > 0

  return (
    <section className="bg-white rounded-xl border border-gray-200 p-6">
      <SectionHeader
        title={t('overview.remediation.title')}
        description={t('overview.remediation.description')}
      />

      {loading ? (
        <p className="mt-4 text-sm text-gray-400">{t('overview.remediation.loadingTrend')}</p>
      ) : !hasActivity ? (
        <EmptyState
          icon={Activity}
          title={t('overview.remediation.emptyTitle')}
          description={t('overview.remediation.emptyDescription')}
        />
      ) : (
        <div className="mt-4 space-y-5">
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
            <TrendStat label={t('overview.remediation.newFindings')} value={totalNew} tone="danger" />
            <TrendStat label={t('overview.remediation.fixed')} value={totalFixed} tone="success" />
            <TrendStat
              label={t('overview.remediation.netBalance')}
              value={net > 0 ? `+${net}` : String(net)}
              tone={net > 0 ? 'danger' : net < 0 ? 'success' : 'neutral'}
              hint={net > 0 ? t('overview.remediation.backlogGrowing') : net < 0 ? t('overview.remediation.backlogShrinking') : t('overview.remediation.stable')}
            />
          </div>

          <div>
            <p className="text-xs font-medium text-gray-500 mb-3">{t('overview.remediation.last14Days')}</p>
            <ResponsiveContainer width="100%" height={180}>
              <BarChart data={chartData} barGap={2} barCategoryGap="20%">
                <XAxis
                  dataKey="label"
                  tick={{ fontSize: 11 }}
                  axisLine={false}
                  tickLine={false}
                  interval="preserveStartEnd"
                />
                <YAxis allowDecimals={false} tick={{ fontSize: 11 }} axisLine={false} tickLine={false} width={28} />
                <Tooltip
                  cursor={{ fill: '#f9fafb' }}
                  contentStyle={{ borderRadius: 8, border: '1px solid #e5e7eb', fontSize: 12 }}
                />
                <Bar dataKey="novos" name={t('overview.remediation.chartNew')} fill="#f97316" radius={[4, 4, 0, 0]} />
                <Bar dataKey="corrigidos" name={t('overview.remediation.chartFixed')} fill="#22c55e" radius={[4, 4, 0, 0]} />
              </BarChart>
            </ResponsiveContainer>
          </div>

          {hasSnapshotTrend && firstSnapshot && lastSnapshot && backlogDelta != null && (
            <div className="rounded-lg bg-gray-50 border border-gray-100 px-4 py-3 flex items-start gap-3">
              {backlogDelta <= 0 ? (
                <TrendingDown className="w-4 h-4 text-green-600 mt-0.5 shrink-0" />
              ) : (
                <TrendingUp className="w-4 h-4 text-red-600 mt-0.5 shrink-0" />
              )}
              <div className="text-sm text-gray-700">
                <span className="font-medium">{t('overview.remediation.backlogCriticalHigh')}</span>
                {firstSnapshot.open_critical + firstSnapshot.open_high} →{' '}
                {lastSnapshot.open_critical + lastSnapshot.open_high}
                <span
                  className={cn(
                    'ml-2 font-medium',
                    backlogDelta > 0 ? 'text-red-600' : backlogDelta < 0 ? 'text-green-600' : 'text-gray-500',
                  )}
                >
                  ({backlogDelta > 0 ? '+' : ''}
                  {backlogDelta})
                </span>
                {lastSnapshot.sla_breach_rate > 0 && (
                  <span className="text-gray-500 ml-2">
                    · {t('overview.remediation.slaBreach', { rate: (lastSnapshot.sla_breach_rate * 100).toFixed(0) })}
                  </span>
                )}
              </div>
            </div>
          )}
        </div>
      )}
    </section>
  )
}

function TrendStat({
  label,
  value,
  tone,
  hint,
}: {
  label: string
  value: number | string
  tone: 'danger' | 'success' | 'neutral'
  hint?: string
}) {
  const toneClasses = {
    danger: 'text-red-700 bg-red-50 ring-red-100',
    success: 'text-green-700 bg-green-50 ring-green-100',
    neutral: 'text-gray-700 bg-gray-50 ring-gray-200',
  }

  return (
    <div className={cn('rounded-lg ring-1 px-4 py-3', toneClasses[tone])}>
      <p className="text-xs text-gray-500">{label}</p>
      <p className="text-2xl font-bold mt-0.5">{value}</p>
      {hint && <p className="text-xs mt-0.5 opacity-80">{hint}</p>}
    </div>
  )
}

function SectionHeader({
  title,
  description,
}: {
  title: string
  description: string
}) {
  return (
    <div>
      <h2 className="text-base font-semibold text-gray-900">{title}</h2>
      <p className="text-sm text-gray-500">{description}</p>
    </div>
  )
}

function KpiCard({
  label,
  value,
  icon: Icon,
  href,
  accent,
}: {
  label: string
  value: number | string
  icon: typeof Activity
  href?: string
  accent?: 'danger' | 'warning'
}) {
  const accentClasses = {
    danger: 'text-red-600 bg-red-50',
    warning: 'text-orange-600 bg-orange-50',
  }

  const content = (
    <article className="bg-white rounded-xl border border-gray-200 p-5 h-full hover:border-gray-300 transition-colors">
      <div className="flex items-center justify-between mb-3">
        <p className="text-sm text-gray-500">{label}</p>
        <div
          className={cn(
            'w-8 h-8 rounded-lg flex items-center justify-center',
            accent ? accentClasses[accent] : 'bg-gray-100 text-gray-400',
          )}
        >
          <Icon className="w-4 h-4" />
        </div>
      </div>
      <p className="text-2xl font-bold text-gray-900">{value}</p>
    </article>
  )

  if (href) {
    return (
      <Link to={href} className="block">
        {content}
      </Link>
    )
  }
  return content
}

function RiskTableSection<T>({
  title,
  description,
  icon: Icon,
  emptyTitle,
  emptyDescription,
  viewAllHref,
  viewAllLabel,
  items,
  renderRow,
}: {
  title: string
  description: string
  icon: typeof GitBranch
  emptyTitle: string
  emptyDescription: string
  viewAllHref: string
  viewAllLabel: string
  items: T[]
  renderRow: (item: T) => ReactNode
}) {
  return (
    <section className="bg-white rounded-xl border border-gray-200 p-6">
      <div className="flex items-start justify-between gap-3 mb-4">
        <div className="flex items-start gap-3">
          <div className="w-9 h-9 rounded-lg bg-gray-100 flex items-center justify-center shrink-0">
            <Icon className="w-4 h-4 text-gray-500" />
          </div>
          <SectionHeader title={title} description={description} />
        </div>
        <Link
          to={viewAllHref}
          className="text-sm text-brand-600 hover:text-brand-700 font-medium shrink-0"
        >
          {viewAllLabel}
        </Link>
      </div>
      {items.length === 0 ? (
        <EmptyState icon={Icon} title={emptyTitle} description={emptyDescription} />
      ) : (
        <div className="divide-y divide-gray-100">{items.map(renderRow)}</div>
      )}
    </section>
  )
}
