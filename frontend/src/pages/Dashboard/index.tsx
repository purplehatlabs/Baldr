import { useQuery } from '@tanstack/react-query'
import { useTranslation } from 'react-i18next'
import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
  Cell,
} from 'recharts'
import { ShieldAlert, ShieldCheck, AlertTriangle, Info, GitBranch, Bug } from 'lucide-react'
import { getDashboard } from '@/api/dashboard'
import { PageSpinner } from '@/components/shared/Spinner'
import { severityColor } from '@/components/shared/SeverityBadge'

export default function DashboardPage() {
  const { t } = useTranslation()
  const { data, isLoading } = useQuery({
    queryKey: ['dashboard'],
    queryFn: getDashboard,
    refetchInterval: 30_000,
  })

  if (isLoading || !data) return <PageSpinner />

  const sev = data.findings_by_severity
  const chartData = [
    { name: t('dashboard.severity.critical'), value: sev.critical, color: severityColor.critical },
    { name: t('dashboard.severity.high'), value: sev.high, color: severityColor.high },
    { name: t('dashboard.severity.medium'), value: sev.medium, color: severityColor.medium },
    { name: t('dashboard.severity.low'), value: sev.low, color: severityColor.low },
  ]

  return (
    <div className="space-y-6">
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        <StatCard
          label={t('dashboard.severity.critical')}
          value={sev.critical}
          icon={ShieldAlert}
          colorClass="text-red-600 bg-red-50"
        />
        <StatCard
          label={t('dashboard.severity.high')}
          value={sev.high}
          icon={AlertTriangle}
          colorClass="text-orange-600 bg-orange-50"
        />
        <StatCard
          label={t('dashboard.severity.medium')}
          value={sev.medium}
          icon={Info}
          colorClass="text-yellow-600 bg-yellow-50"
        />
        <StatCard
          label={t('dashboard.severity.fixed')}
          value={data.fixed_findings}
          icon={ShieldCheck}
          colorClass="text-green-600 bg-green-50"
        />
      </div>

      <div className="grid grid-cols-2 gap-4">
        <div className="bg-white rounded-xl border border-gray-200 p-5 flex items-center gap-4">
          <div className="w-10 h-10 rounded-lg flex items-center justify-center bg-gray-100">
            <GitBranch className="w-5 h-5 text-gray-600" />
          </div>
          <div>
            <p className="text-2xl font-bold text-gray-900">{data.total_repos}</p>
            <p className="text-sm text-gray-500">{t('dashboard.monitoredRepos')}</p>
          </div>
        </div>
        <div className="bg-white rounded-xl border border-gray-200 p-5 flex items-center gap-4">
          <div className="w-10 h-10 rounded-lg flex items-center justify-center bg-gray-100">
            <Bug className="w-5 h-5 text-gray-600" />
          </div>
          <div>
            <p className="text-2xl font-bold text-gray-900">{data.open_findings}</p>
            <p className="text-sm text-gray-500">{t('dashboard.openFindings')}</p>
          </div>
        </div>
      </div>

      <div className="bg-white rounded-xl border border-gray-200 p-6">
        <h2 className="font-semibold text-gray-900 mb-6">{t('dashboard.findingsBySeverity')}</h2>
        {data.total_findings === 0 ? (
          <div className="text-center py-12 text-gray-400 text-sm">{t('dashboard.emptyChart')}</div>
        ) : (
          <ResponsiveContainer width="100%" height={220}>
            <BarChart data={chartData} barCategoryGap="30%">
              <XAxis dataKey="name" tick={{ fontSize: 13 }} axisLine={false} tickLine={false} />
              <YAxis allowDecimals={false} tick={{ fontSize: 12 }} axisLine={false} tickLine={false} />
              <Tooltip
                cursor={{ fill: '#f3f4f6' }}
                contentStyle={{ borderRadius: 8, border: '1px solid #e5e7eb', fontSize: 13 }}
              />
              <Bar dataKey="value" radius={[6, 6, 0, 0]}>
                {chartData.map((entry) => (
                  <Cell key={entry.name} fill={entry.color} />
                ))}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        )}
      </div>
    </div>
  )
}

function StatCard({
  label,
  value,
  icon: Icon,
  colorClass,
}: {
  label: string
  value: number
  icon: typeof ShieldAlert
  colorClass: string
}) {
  return (
    <div className="bg-white rounded-xl border border-gray-200 p-5 flex items-center gap-4">
      <div className={`w-10 h-10 rounded-lg flex items-center justify-center ${colorClass}`}>
        <Icon className="w-5 h-5" />
      </div>
      <div>
        <p className="text-2xl font-bold text-gray-900">{value}</p>
        <p className="text-sm text-gray-500">{label}</p>
      </div>
    </div>
  )
}
