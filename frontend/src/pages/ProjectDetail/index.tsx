import { Link, useParams } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import { useTranslation } from 'react-i18next'
import { FolderKanban } from 'lucide-react'
import { getProject } from '@/api/projects'
import { PageSpinner } from '@/components/shared/Spinner'
import { EmptyState } from '@/components/shared/EmptyState'
import { getAppLocale } from '@/i18n'
import { formatDateTime } from '@/lib/locale'

export default function ProjectDetailPage() {
  const { t } = useTranslation()
  const { id } = useParams<{ id: string }>()
  const locale = getAppLocale()

  const { data: project, isLoading } = useQuery({
    queryKey: ['project', id],
    queryFn: () => getProject(id as string),
    enabled: Boolean(id),
  })

  if (!id) {
    return (
      <div className="bg-white rounded-xl border border-gray-200">
        <EmptyState
          icon={FolderKanban}
          title={t('projectDetail.invalidTitle')}
          description={t('projectDetail.invalidDescription')}
        />
      </div>
    )
  }

  if (isLoading) return <PageSpinner />

  if (!project) {
    return (
      <div className="bg-white rounded-xl border border-gray-200">
        <EmptyState
          icon={FolderKanban}
          title={t('projectDetail.notFoundTitle')}
          description={t('projectDetail.notFoundDescription')}
        />
      </div>
    )
  }

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-xl font-semibold text-gray-900">{project.repo || project.id}</h2>
          <p className="text-sm text-gray-500">{t('projectDetail.subtitle')}</p>
        </div>
        <Link
          to="/projects"
          className="inline-flex items-center rounded-lg px-3 py-1.5 text-sm border border-gray-200 text-gray-700 hover:bg-gray-50 transition-colors"
        >
          {t('common.back')}
        </Link>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        <InfoCard label={t('projectDetail.fields.defaultBranch')} value={project.default_branch || '—'} />
        <InfoCard
          label={t('projectDetail.fields.archived')}
          value={project.is_archived ? t('common.yes') : t('common.no')}
        />
        <InfoCard label={t('projectDetail.fields.openFindings')} value={String(project.open_total)} />
        <InfoCard label={t('projectDetail.fields.criticalFindings')} value={String(project.open_critical)} />
        <InfoCard label={t('projectDetail.fields.highFindings')} value={String(project.open_high)} />
        <InfoCard label={t('projectDetail.fields.fixedFindings')} value={String(project.fixed_total)} />
        <InfoCard
          label={t('projectDetail.fields.lastScan')}
          value={project.last_scanned_at ? formatDateTime(project.last_scanned_at, locale) : '—'}
        />
      </div>

      <div className="bg-white rounded-xl border border-gray-200 p-5">
        <h3 className="text-sm font-semibold text-gray-900 mb-3">{t('projectDetail.identifiers')}</h3>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-sm">
          <p className="text-gray-600">
            <span className="text-gray-500">ID:</span>{' '}
            <span className="font-mono">{project.id}</span>
          </p>
          <p className="text-gray-600">
            <span className="text-gray-500">{t('projectDetail.repo')}:</span> {project.repo}
          </p>
        </div>
      </div>
    </div>
  )
}

function InfoCard({ label, value }: { label: string; value: string }) {
  return (
    <article className="bg-white rounded-xl border border-gray-200 p-5">
      <p className="text-xs text-gray-500 mb-1">{label}</p>
      <p className="text-base font-medium text-gray-900">{value}</p>
    </article>
  )
}
