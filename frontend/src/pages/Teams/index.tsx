import { useEffect, useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { useTranslation } from 'react-i18next'
import { Users, ChevronDown, ChevronRight } from 'lucide-react'
import { listTeams, getTeamFindings, getTeamMembers } from '@/api/teams'
import { SeverityBadge } from '@/components/shared/SeverityBadge'
import { PageSpinner } from '@/components/shared/Spinner'
import { EmptyState } from '@/components/shared/EmptyState'
import { cn } from '@/lib/utils'
import type { Team } from '@/api/teams'
import type { Finding } from '@/api/findings'

export default function TeamsPage() {
  const { t } = useTranslation()
  const { data: teams = [], isLoading } = useQuery({
    queryKey: ['teams'],
    queryFn: listTeams,
  })

  const [expanded, setExpanded] = useState<string | null>(null)

  if (isLoading) return <PageSpinner />

  if (teams.length === 0) {
    return (
      <div className="bg-white rounded-xl border border-gray-200">
        <EmptyState
          icon={Users}
          title={t('teams.emptyTitle')}
          description={t('teams.emptyDescription')}
        />
      </div>
    )
  }

  return (
    <div className="space-y-3">
      <p className="text-sm text-gray-500">{t('teams.detected', { count: teams.length })}</p>
      {teams.map((team) => (
        <TeamCard
          key={team.id}
          team={team}
          isExpanded={expanded === team.id}
          onToggle={() => setExpanded(expanded === team.id ? null : team.id)}
        />
      ))}
    </div>
  )
}

type TeamCardTab = 'members' | 'findings'

function TeamCard({
  team,
  isExpanded,
  onToggle,
}: {
  team: Team
  isExpanded: boolean
  onToggle: () => void
}) {
  const { t } = useTranslation()
  const [tab, setTab] = useState<TeamCardTab>('members')

  useEffect(() => {
    if (!isExpanded) setTab('members')
  }, [isExpanded])

  const { data: members = [], isLoading: membersLoading } = useQuery({
    queryKey: ['team-members', team.id],
    queryFn: () => getTeamMembers(team.id),
    enabled: isExpanded,
  })

  const { data: findings = [], isLoading: findingsLoading } = useQuery({
    queryKey: ['team-findings', team.id],
    queryFn: () => getTeamFindings(team.id),
    enabled: isExpanded,
  })

  return (
    <div className="bg-white rounded-xl border border-gray-200 overflow-hidden">
      <button
        className="w-full px-6 py-4 flex items-center gap-4 hover:bg-gray-50 transition-colors text-left"
        onClick={onToggle}
      >
        <div className="flex items-center justify-center w-9 h-9 rounded-lg bg-gray-100 flex-shrink-0">
          <Users className="w-4 h-4 text-gray-500" />
        </div>
        <div className="flex-1 min-w-0">
          <p className="font-semibold text-gray-900">{team.display_name}</p>
          <p className="text-xs text-gray-500">@{team.github_team_slug}</p>
        </div>
        <div className="flex items-center gap-2 flex-shrink-0">
          {team.critical > 0 && <SeverityPill value={team.critical} color="bg-red-100 text-red-700" />}
          {team.high > 0 && <SeverityPill value={team.high} color="bg-orange-100 text-orange-700" />}
          {team.medium > 0 && <SeverityPill value={team.medium} color="bg-yellow-100 text-yellow-700" />}
          {team.low > 0 && <SeverityPill value={team.low} color="bg-blue-100 text-blue-700" />}
          {team.total === 0 && <span className="text-xs text-gray-400">{t('teams.noFindings')}</span>}
        </div>
        <div className="ml-2 text-gray-400">
          {isExpanded ? <ChevronDown className="w-4 h-4" /> : <ChevronRight className="w-4 h-4" />}
        </div>
      </button>

      {isExpanded && (
        <div className="border-t border-gray-100">
          <div className="flex gap-1 px-6 pt-3 border-b border-gray-100">
            <button
              type="button"
              onClick={(e) => {
                e.stopPropagation()
                setTab('members')
              }}
              className={cn(
                'px-3 py-2 text-sm font-medium rounded-t-lg transition-colors',
                tab === 'members'
                  ? 'text-gray-900 bg-gray-50 border border-b-0 border-gray-100 -mb-px'
                  : 'text-gray-500 hover:text-gray-700',
              )}
            >
              {t('teams.tabs.members')}
            </button>
            <button
              type="button"
              onClick={(e) => {
                e.stopPropagation()
                setTab('findings')
              }}
              className={cn(
                'px-3 py-2 text-sm font-medium rounded-t-lg transition-colors',
                tab === 'findings'
                  ? 'text-gray-900 bg-gray-50 border border-b-0 border-gray-100 -mb-px'
                  : 'text-gray-500 hover:text-gray-700',
              )}
            >
              {t('teams.tabs.findings')}
            </button>
          </div>

          {tab === 'members' &&
            (membersLoading ? (
              <div className="px-6 py-4 text-sm text-gray-400">{t('teams.loadingMembers')}</div>
            ) : members.length === 0 ? (
              <div className="px-6 py-6 text-sm text-gray-500 leading-relaxed">{t('teams.noMembers')}</div>
            ) : (
              <ul className="divide-y divide-gray-50">
                {members.map((m) => (
                  <li
                    key={m.id}
                    className={cn(
                      'px-6 py-3 flex items-center gap-3 hover:bg-gray-50 transition-colors',
                      !m.is_active && 'opacity-60',
                    )}
                  >
                    {m.avatar_url ? (
                      <img
                        src={m.avatar_url}
                        alt=""
                        className="w-10 h-10 rounded-full flex-shrink-0 bg-gray-100"
                      />
                    ) : (
                      <div className="w-10 h-10 rounded-full flex-shrink-0 bg-gray-100 flex items-center justify-center text-sm font-medium text-gray-500">
                        {m.github_login.charAt(0).toUpperCase()}
                      </div>
                    )}
                    <div className="min-w-0 flex-1">
                      <p className="text-sm truncate">
                        <span className="text-gray-600">@{m.github_login}</span>
                        {m.name ? <span className="ml-2 font-medium text-gray-900">{m.name}</span> : null}
                      </p>
                    </div>
                    <div className="flex items-center gap-2 flex-shrink-0">
                      {m.user_id ? (
                        <span className="inline-flex items-center rounded-full px-2 py-0.5 text-xs font-medium bg-violet-100 text-violet-800">
                          {t('teams.linkedUser')}
                        </span>
                      ) : null}
                    </div>
                  </li>
                ))}
              </ul>
            ))}

          {tab === 'findings' &&
            (findingsLoading ? (
              <div className="px-6 py-4 text-sm text-gray-400">{t('teams.loadingFindings')}</div>
            ) : findings.length === 0 ? (
              <div className="px-6 py-4 text-sm text-gray-400">{t('teams.noOpenFindings')}</div>
            ) : (
              <table className="w-full text-sm">
                <thead>
                  <tr className="bg-gray-50 border-b border-gray-100">
                    <th className="px-6 py-2.5 text-left text-xs font-medium text-gray-500">
                      {t('teams.columns.severity')}
                    </th>
                    <th className="px-6 py-2.5 text-left text-xs font-medium text-gray-500">
                      {t('teams.columns.package')}
                    </th>
                    <th className="px-6 py-2.5 text-left text-xs font-medium text-gray-500">
                      {t('teams.columns.osvId')}
                    </th>
                    <th className="px-6 py-2.5 text-left text-xs font-medium text-gray-500">
                      {t('teams.columns.repoManifest')}
                    </th>
                    <th className="px-6 py-2.5 text-left text-xs font-medium text-gray-500">
                      {t('teams.columns.fix')}
                    </th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-gray-50">
                  {findings.map((f) => (
                    <TeamFindingRow key={f.id} finding={f} />
                  ))}
                </tbody>
              </table>
            ))}
        </div>
      )}
    </div>
  )
}

function TeamFindingRow({ finding }: { finding: Finding }) {
  return (
    <tr className="hover:bg-gray-50 transition-colors">
      <td className="px-6 py-3">
        <SeverityBadge severity={finding.severity} size="sm" />
      </td>
      <td className="px-6 py-3">
        <span className="font-medium text-gray-900">{finding.package_name}</span>
        <span className="text-gray-400 ml-1 text-xs">@{finding.package_version}</span>
      </td>
      <td className="px-6 py-3 font-mono text-xs text-gray-600">{finding.osv_id}</td>
      <td className="px-6 py-3 text-xs text-gray-500">
        <div className="truncate max-w-[200px]">{finding.repo_full_name}</div>
        <div className="truncate max-w-[200px] font-mono text-gray-400">{finding.manifest_path}</div>
      </td>
      <td className="px-6 py-3">
        {finding.fixed_version ? (
          <span className="text-xs font-mono text-green-700">{finding.fixed_version}</span>
        ) : (
          <span className="text-xs text-gray-400">—</span>
        )}
      </td>
    </tr>
  )
}

function SeverityPill({ value, color }: { value: number; color: string }) {
  return (
    <span className={`inline-flex items-center rounded-full px-2 py-0.5 text-xs font-semibold ${color}`}>
      {value}
    </span>
  )
}
