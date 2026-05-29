import i18n from 'i18next'
import { initReactI18next } from 'react-i18next'
import enCommon from './en/common.json'
import ptBRCommon from './pt-BR/common.json'
import { DEFAULT_LOCALE, LOCALE_STORAGE_KEY, normalizeLocale, type AppLocale } from './languages'

const storedLocale = normalizeLocale(
  typeof window !== 'undefined' ? localStorage.getItem(LOCALE_STORAGE_KEY) : null,
)

void i18n.use(initReactI18next).init({
  resources: {
    en: { common: enCommon },
    'pt-BR': { common: ptBRCommon },
  },
  lng: storedLocale,
  fallbackLng: DEFAULT_LOCALE,
  defaultNS: 'common',
  ns: ['common'],
  interpolation: {
    escapeValue: false,
  },
})

export function setAppLocale(locale: AppLocale) {
  const normalized = normalizeLocale(locale)
  localStorage.setItem(LOCALE_STORAGE_KEY, normalized)
  void i18n.changeLanguage(normalized)
  return normalized
}

export function getAppLocale(): AppLocale {
  return normalizeLocale(i18n.language)
}

export default i18n
