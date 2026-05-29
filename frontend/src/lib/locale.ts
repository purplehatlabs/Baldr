import { localeToIntlTag, type AppLocale } from '@/i18n/languages'

export function formatDateTime(value: string | Date, locale: AppLocale): string {
  const date = value instanceof Date ? value : new Date(value)
  return date.toLocaleString(localeToIntlTag(locale))
}
