import { Link } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import { useTranslation } from 'react-i18next'
import { FolderKanban } from 'lucide-react'
import { listProjects } from '@/api/projects'
import { PageSpinner } from '@/components/shared/Spinner'
import { EmptyState } from '@/components/shared/EmptyState'
import { getAppLocale } from '@/i18n'
import { formatDateTime } from '@/lib/locale'

export default function ProjectsPage() {
  const { t } = useTranslation()
  const { data, isLoading } = useQuery({
    queryKey: ['projects', 1, 20],
    queryFn: () => listProjects(1, 20),
  })

  if (isLoading) return <PageSpinner />

  const projects = data?.items ?? []
  const locale = getAppLocale()

  if (projects.length === 0) {
    return (
      <div className="bg-white rounded-xl border border-gray-200">
        <EmptyState
          icon={FolderKanban}
          title={t('projects.emptyTitle')}
          description={t('projects.emptyDescription')}
        />
      </div>
    )
  }

  return (
    <div className="bg-white rounded-xl border border-gray-200 overflow-hidden">
      <div className="px-6 py-4 border-b border-gray-100 flex items-center justify-between">
        <h2 className="font-semibold text-gray-900">
          {t('projects.count', { count: data?.total ?? projects.length })}
        </h2>
      </div>
      <table className="w-full text-sm">
        <thead>
          <tr className="border-b border-gray-100 bg-gray-50">
            <th className="px-6 py-3 text-left font-medium text-gray-500">{t('projects.columns.project')}</th>
            <th className="px-6 py-3 text-left font-medium text-gray-500">{t('projects.columns.lastScan')}</th>
            <th className="px-6 py-3 text-left font-medium text-gray-500">{t('projects.columns.open')}</th>
            <th className="px-6 py-3 text-left font-medium text-gray-500">{t('projects.columns.critical')}</th>
            <th className="px-6 py-3 text-left font-medium text-gray-500">{t('projects.columns.high')}</th>
            <th className="px-6 py-3 text-right font-medium text-gray-500">{t('projects.columns.detail')}</th>
          </tr>
        </thead>
        <tbody className="divide-y divide-gray-50">
          {projects.map((project) => (
            <tr key={project.id} className="hover:bg-gray-50 transition-colors">
              <td className="px-6 py-3">
                <p className="font-medium text-gray-900">{project.repo || project.id}</p>
              </td>
              <td className="px-6 py-3 text-gray-600">
                {project.last_scanned_at ? formatDateTime(project.last_scanned_at, locale) : '—'}
              </td>
              <td className="px-6 py-3 text-gray-600">{project.open_total}</td>
              <td className="px-6 py-3 text-gray-600">{project.open_critical}</td>
              <td className="px-6 py-3 text-gray-600">{project.open_high}</td>
              <td className="px-6 py-3 text-right">
                <Link
                  to={`/projects/${project.id}`}
                  className="inline-flex items-center rounded-lg px-3 py-1.5 text-xs font-medium bg-brand-50 text-brand-700 hover:bg-brand-100 transition-colors"
                >
                  {t('common.open')}
                </Link>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}
