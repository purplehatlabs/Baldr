import { Outlet, useLocation } from 'react-router-dom'
import { useTranslation } from 'react-i18next'
import Sidebar from './Sidebar'
import Header from './Header'

export default function AppLayout() {
  const { pathname } = useLocation()
  const { t } = useTranslation()

  const pageTitles: Record<string, string> = {
    '/overview': t('nav.overview'),
    '/triage': t('nav.triage'),
    '/manual-vulnerabilities': t('nav.manualVulnerabilities'),
    '/projects': t('nav.projects'),
    '/teams': t('nav.teams'),
    '/policies': t('nav.policies'),
    '/integrations': t('nav.integrations'),
    '/settings': t('nav.settings'),
    '/dashboard': t('nav.overview'),
    '/findings': t('nav.triage'),
    '/repositories': t('nav.repositories'),
    '/scans': t('nav.scans'),
  }

  const title = pathname.startsWith('/projects/')
    ? t('layout.projectDetails')
    : pageTitles[pathname] ?? t('layout.defaultTitle')

  return (
    <div className="flex min-h-screen">
      <Sidebar />
      <div className="flex-1 flex flex-col">
        <Header title={title} />
        <main className="flex-1 p-6 overflow-auto">
          <Outlet />
        </main>
      </div>
    </div>
  )
}
