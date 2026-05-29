export const SUPPORTED_LOCALES = ['en', 'pt-BR'] as const

export type AppLocale = (typeof SUPPORTED_LOCALES)[number]

export const DEFAULT_LOCALE: AppLocale = 'en'

export const LOCALE_STORAGE_KEY = 'devsecops.locale'

export function normalizeLocale(raw?: string | null): AppLocale {
  if (!raw) return DEFAULT_LOCALE
  const value = raw.trim().toLowerCase()
  if (value === 'pt-br' || value === 'pt_br' || value === 'ptbr') {
    return 'pt-BR'
  }
  return DEFAULT_LOCALE
}

export function localeToIntlTag(locale: AppLocale): string {
  return locale === 'pt-BR' ? 'pt-BR' : 'en-US'
}
