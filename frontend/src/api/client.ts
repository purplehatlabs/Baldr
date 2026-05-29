import axios from 'axios'
import { LOCALE_STORAGE_KEY, normalizeLocale } from '@/i18n/languages'

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
      window.location.href = '/login'
    }
    return Promise.reject(error)
  },
)
