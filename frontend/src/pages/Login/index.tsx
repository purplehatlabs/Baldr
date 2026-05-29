import { useEffect, useMemo, useState } from 'react'
import { useLocation, useNavigate } from 'react-router-dom'
import { useMutation, useQueryClient } from '@tanstack/react-query'
import { useTranslation } from 'react-i18next'
import { ShieldCheck, Terminal, AlertCircle } from 'lucide-react'
import {
  getGitHubLoginURL,
  getGoogleLoginURL,
  isDevAuthEnabled,
  isGitHubSSOEnabled,
  isGoogleSSOEnabled,
  devLogin,
} from '@/api/auth'
import { getNextPathFromSearch, savePostLoginRedirect } from '@/lib/postLoginRedirect'

export default function LoginPage() {
  const { t } = useTranslation()
  const location = useLocation()
  const githubEnabled = isGitHubSSOEnabled()
  const googleEnabled = isGoogleSSOEnabled()
  const nextPath = useMemo(() => getNextPathFromSearch(location.search), [location.search])

  useEffect(() => {
    if (nextPath) {
      savePostLoginRedirect(nextPath)
    }
  }, [nextPath])

  const features = [
    { value: '30+', label: t('login.features.ecosystems') },
    { value: '1M+', label: t('login.features.vulnerabilities') },
    { value: 'OSV', label: t('login.features.database') },
  ]

  return (
    <div className="min-h-screen flex items-center justify-center bg-gradient-to-br from-gray-900 via-gray-800 to-gray-900">
      <div className="w-full max-w-md p-8 space-y-8">
        <div className="flex flex-col items-center space-y-3">
          <div className="flex items-center justify-center w-16 h-16 rounded-2xl bg-brand-500 shadow-lg">
            <ShieldCheck className="w-9 h-9 text-white" />
          </div>
          <h1 className="text-3xl font-bold text-white tracking-tight">{t('app.name')}</h1>
          <p className="text-gray-400 text-sm text-center">{t('login.tagline')}</p>
        </div>

        <div className="bg-white/5 border border-white/10 rounded-2xl p-8 backdrop-blur-sm space-y-6">
          <div className="space-y-1">
            <h2 className="text-white font-semibold text-lg">{t('login.title')}</h2>
            <p className="text-gray-400 text-sm">
              {githubEnabled ? t('login.githubHint') : t('login.googleHint')}
            </p>
          </div>

          {githubEnabled && (
            <a
              href={getGitHubLoginURL(nextPath ?? undefined)}
              className="flex items-center justify-center gap-3 w-full py-3 px-4 rounded-xl bg-gray-900 hover:bg-gray-800 transition-colors text-white font-medium shadow-sm border border-white/10"
            >
              <GitHubIcon />
              {t('login.continueGithub')}
            </a>
          )}

          {googleEnabled && (
            <a
              href={getGoogleLoginURL(nextPath ?? undefined)}
              className={`flex items-center justify-center gap-3 w-full py-3 px-4 rounded-xl transition-colors font-medium shadow-sm ${
                githubEnabled
                  ? 'bg-white/10 hover:bg-white/15 text-white border border-white/10'
                  : 'bg-white hover:bg-gray-50 text-gray-800'
              }`}
            >
              <GoogleIcon />
              {t('login.continueGoogle')}
            </a>
          )}

          {isDevAuthEnabled() && (
            <>
              <div className="flex items-center gap-3">
                <div className="flex-1 h-px bg-white/10" />
                <span className="text-gray-600 text-xs">{t('login.or')}</span>
                <div className="flex-1 h-px bg-white/10" />
              </div>
              <DevLoginForm nextPath={nextPath} />
            </>
          )}

          <p className="text-gray-500 text-xs text-center">{t('login.terms')}</p>
        </div>

        <div className="grid grid-cols-3 gap-4">
          {features.map((f) => (
            <div key={f.label} className="text-center space-y-1">
              <div className="text-brand-500 font-bold text-2xl">{f.value}</div>
              <div className="text-gray-500 text-xs">{f.label}</div>
            </div>
          ))}
        </div>
      </div>
    </div>
  )
}

function DevLoginForm({ nextPath }: { nextPath: string | null }) {
  const { t } = useTranslation()
  const [email, setEmail] = useState('dev@example.com')
  const [name, setName] = useState('Dev User')
  const [error, setError] = useState('')
  const navigate = useNavigate()
  const queryClient = useQueryClient()

  const mutation = useMutation({
    mutationFn: () => devLogin(email, name),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['auth', 'me'] })
      navigate(nextPath ?? '/', { replace: true })
    },
    onError: () => setError(t('login.devLoginError')),
  })

  return (
    <div className="space-y-3">
      <div className="flex items-center gap-2 text-yellow-500 text-xs">
        <Terminal className="w-3.5 h-3.5 flex-shrink-0" />
        <span className="font-medium">{t('login.devMode')}</span>
      </div>

      <input
        type="email"
        value={email}
        onChange={(e) => setEmail(e.target.value)}
        placeholder={t('login.emailPlaceholder')}
        className="w-full bg-white/10 border border-white/20 rounded-xl px-4 py-2.5 text-white text-sm placeholder-gray-500 focus:outline-none focus:ring-2 focus:ring-brand-500"
      />
      <input
        type="text"
        value={name}
        onChange={(e) => setName(e.target.value)}
        placeholder={t('login.namePlaceholder')}
        className="w-full bg-white/10 border border-white/20 rounded-xl px-4 py-2.5 text-white text-sm placeholder-gray-500 focus:outline-none focus:ring-2 focus:ring-brand-500"
      />

      {error && (
        <p className="flex items-center gap-1.5 text-red-400 text-xs">
          <AlertCircle className="w-3.5 h-3.5 flex-shrink-0" /> {error}
        </p>
      )}

      <button
        onClick={() => {
          setError('')
          mutation.mutate()
        }}
        disabled={mutation.isPending || !email}
        className="w-full py-2.5 px-4 rounded-xl bg-yellow-500 hover:bg-yellow-400 transition-colors text-gray-900 font-medium text-sm disabled:opacity-50"
      >
        {mutation.isPending ? t('login.devLoggingIn') : t('login.devLogin')}
      </button>
    </div>
  )
}

function GitHubIcon() {
  return (
    <svg className="w-5 h-5" viewBox="0 0 24 24" fill="currentColor" aria-hidden="true">
      <path d="M12 0C5.37 0 0 5.37 0 12c0 5.31 3.435 9.795 8.205 11.385.6.105.825-.255.825-.57 0-.285-.015-1.23-.015-2.235-3.015.555-3.795-.735-4.035-1.41-.135-.345-.72-1.41-1.23-1.935-.42-.45-1.02-.765-1.23-.975-.42-.435-.03-.855.015-1.2.015-.135.195-1.125.825-1.785-2.25-.255-4.635-1.125-4.635-5.01 0-1.11.39-2.01 1.035-2.715.105-.255.45-1.275-.105-2.655 0 0 .84-.27 2.755 1.035.795-.225 1.65-.345 2.505-.345.855 0 1.71.12 2.505.345 1.905-1.305 2.755-1.035 2.755-1.035-.555 1.38-.21 2.4-.105 2.655.645.705 1.035 1.605 1.035 2.715 0 3.9-2.385 4.755-4.635 5.01.36.315.675.915.675 1.845 0 1.335-.015 2.415-.015 2.745 0 .27.225.585.825.48A12.02 12.02 0 0 0 24 12c0-6.63-5.37-12-12-12Z" />
    </svg>
  )
}

function GoogleIcon() {
  return (
    <svg className="w-5 h-5" viewBox="0 0 24 24">
      <path fill="#4285F4" d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z" />
      <path fill="#34A853" d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z" />
      <path fill="#FBBC05" d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l2.85-2.22.81-.62z" />
      <path fill="#EA4335" d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z" />
    </svg>
  )
}
