import { BrowserRouter, Routes, Route, Navigate, useLocation } from 'react-router-dom'
import { useAuth } from '@/hooks/useAuth'
import AppLayout from '@/components/layout/AppLayout'
import LoginPage from '@/pages/Login'
import FindingsPage from '@/pages/Findings'
import TeamsPage from '@/pages/Teams'
import SettingsPage from '@/pages/Settings'
import OverviewPage from '@/pages/Overview'
import ProjectsPage from '@/pages/Projects'
import ProjectDetailPage from '@/pages/ProjectDetail'
import PoliciesPage from '@/pages/Policies'
import IntegrationsPage from '@/pages/Integrations'
import RepositoriesPage from '@/pages/Repositories'
import ScansPage from '@/pages/Scans'
import SupplyChainSignalsPage from '@/pages/SupplyChainSignals'
import ManualVulnerabilitiesPage from '@/pages/ManualVulnerabilities'
import AcceptInvitePage from '@/pages/AcceptInvite'
import { buildLoginPath, popPostLoginRedirect } from '@/lib/postLoginRedirect'

function FindingsRedirect() {
  const location = useLocation()
  return <Navigate to={`/triage${location.search}`} replace />
}

function ProtectedRoutes() {
  const { isAuthenticated, isLoading } = useAuth()
  const location = useLocation()

  if (isLoading) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-gray-50">
        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-brand-500" />
      </div>
    )
  }

  if (!isAuthenticated) {
    const nextPath = `${location.pathname}${location.search}${location.hash}`
    return <Navigate to={buildLoginPath(nextPath)} replace />
  }

  return <AppLayout />
}

function HomeRedirect() {
  const nextPath = popPostLoginRedirect()
  return <Navigate to={nextPath ?? '/overview'} replace />
}

export default function App() {
  return (
    <BrowserRouter>
      <Routes>
        <Route path="/login" element={<LoginPage />} />
        <Route path="/invite/:token" element={<AcceptInvitePage />} />
        <Route element={<ProtectedRoutes />}>
          <Route path="/" element={<HomeRedirect />} />
          <Route path="/overview" element={<OverviewPage />} />
          <Route path="/triage" element={<FindingsPage />} />
          <Route path="/projects" element={<ProjectsPage />} />
          <Route path="/projects/:id" element={<ProjectDetailPage />} />
          <Route path="/repositories" element={<RepositoriesPage />} />
          <Route path="/scans" element={<ScansPage />} />
          <Route path="/supply-chain-signals" element={<SupplyChainSignalsPage />} />
          <Route path="/manual-vulnerabilities" element={<ManualVulnerabilitiesPage />} />
          <Route path="/teams" element={<TeamsPage />} />
          <Route path="/policies" element={<PoliciesPage />} />
          <Route path="/integrations" element={<IntegrationsPage />} />
          <Route path="/settings" element={<SettingsPage />} />

          {/* Backward compatibility */}
          <Route path="/dashboard" element={<Navigate to="/overview" replace />} />
          <Route path="/findings" element={<FindingsRedirect />} />
        </Route>
      </Routes>
    </BrowserRouter>
  )
}
