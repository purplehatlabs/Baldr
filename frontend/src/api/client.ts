import axios from 'axios'
import { LOCALE_STORAGE_KEY, normalizeLocale } from '@/i18n/languages'
import { buildLoginPath } from '@/lib/postLoginRedirect'

export const api = axios.create({
  baseURL: import.meta.env.VITE_API_BASE_URL || '',
  withCredentials: true, // send httpOnly cookies
})

api.interceptors.request.use((config) => {
  const locale = normalizeLocale(
    typeof window !== 'undefined' ? localStorage.getItem(LOCALE_STORAGE_KEY) : null,
  )
  config.headers.set('Accept-Language', locale)
  return config
})

api.interceptors.response.use(
  (response) => response,
  (error) => {
    if (error.response?.status === 401) {
      if (window.location.pathname !== '/login') {
        const nextPath = `${window.location.pathname}${window.location.search}${window.location.hash}`
        window.location.href = buildLoginPath(nextPath)
      }
    }
    return Promise.reject(error)
  },
)
