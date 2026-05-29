import React, { useEffect } from 'react'
import ReactDOM from 'react-dom/client'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { I18nextProvider } from 'react-i18next'
import App from './App'
import i18n, { setAppLocale } from './i18n'
import { normalizeLocale } from './i18n/languages'
import './index.css'

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      retry: 1,
      staleTime: 30_000,
    },
  },
})

function LocaleBootstrap({ children }: { children: React.ReactNode }) {
  useEffect(() => {
    void (async () => {
      try {
        const { getMe } = await import('./api/auth')
        const user = await getMe()
        if (user.language) {
          setAppLocale(normalizeLocale(user.language))
        }
      } catch {
        // unauthenticated bootstrap is expected on /login
      }
    })()
  }, [])

  return <>{children}</>
}

ReactDOM.createRoot(document.getElementById('root')!).render(
  <React.StrictMode>
    <QueryClientProvider client={queryClient}>
      <I18nextProvider i18n={i18n}>
        <LocaleBootstrap>
          <App />
        </LocaleBootstrap>
      </I18nextProvider>
    </QueryClientProvider>
  </React.StrictMode>,
)
