import { NavLink } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import { useTranslation } from 'react-i18next'
import {
  ShieldCheck,
  LayoutDashboard,
  FolderKanban,
  GitBranch,
  Bug,
  Users,
  Shield,
  Plug,
  Settings,
  Activity,
  AlertTriangle,
  FileWarning,
} from 'lucide-react'
import { cn } from '@/lib/utils'
import { getScanJobsSummary } from '@/api/scanJobs'

export default function Sidebar() {
  const { t } = useTranslation()
  const { data: scanSummary } = useQuery({
    queryKey: ['scan-jobs-summary'],
    queryFn: getScanJobsSummary,
    refetchInterval: (query) =>
      (query.state.data?.total_active ?? 0) > 0 ? 5000 : false,
  })

  const navItems = [
    { to: '/overview', icon: LayoutDashboard, label: t('nav.overview') },
    { to: '/triage', icon: Bug, label: t('nav.triage') },
    { to: '/manual-vulnerabilities', icon: FileWarning, label: t('nav.manualVulnerabilities') },
    { to: '/projects', icon: FolderKanban, label: t('nav.projects') },
    { to: '/repositories', icon: GitBranch, label: t('nav.repositories') },
    { to: '/scans', icon: Activity, label: t('nav.scans'), showActiveBadge: true },
    { to: '/supply-chain-signals', icon: AlertTriangle, label: t('nav.supplyChainSignals') },
    { to: '/teams', icon: Users, label: t('nav.teams') },
    { to: '/policies', icon: Shield, label: t('nav.policies') },
    { to: '/integrations', icon: Plug, label: t('nav.integrations') },
    { to: '/settings', icon: Settings, label: t('nav.settings') },
  ]

  const activeScans = scanSummary?.total_active ?? 0

  return (
    <aside className="w-64 min-h-screen bg-gray-900 flex flex-col">
      <div className="flex items-center gap-3 px-6 py-5 border-b border-white/10">
        <div className="flex items-center justify-center w-8 h-8 rounded-lg bg-brand-500">
          <ShieldCheck className="w-5 h-5 text-white" />
        </div>
        <span className="text-white font-bold text-lg">{t('app.name')}</span>
      </div>

      <nav className="flex-1 px-3 py-4 space-y-1">
        {navItems.map(({ to, icon: Icon, label, showActiveBadge }) => (
          <NavLink
            key={to}
            to={to}
            className={({ isActive }) =>
              cn(
                'flex items-center gap-3 px-3 py-2 rounded-lg text-sm font-medium transition-colors',
                isActive
                  ? 'bg-brand-600 text-white'
                  : 'text-gray-400 hover:text-white hover:bg-white/5',
              )
            }
          >
            <Icon className="w-4 h-4" />
            <span className="flex-1">{label}</span>
            {showActiveBadge && activeScans > 0 && (
              <span className="inline-flex items-center justify-center min-w-[1.25rem] h-5 px-1.5 rounded-full bg-amber-500 text-white text-[10px] font-bold">
                {activeScans}
              </span>
            )}
          </NavLink>
        ))}
      </nav>
    </aside>
  )
}
