import { useMutation, useQueryClient } from '@tanstack/react-query'
import { useTranslation } from 'react-i18next'
import { updateUserPreferences, type AppLanguage } from '@/api/auth'
import { getAppLocale, setAppLocale } from '@/i18n'
import { type AppLocale } from '@/i18n/languages'

export function useLanguage() {
  const { i18n } = useTranslation()
  const queryClient = useQueryClient()

  const mutation = useMutation({
    mutationFn: (language: AppLanguage) => updateUserPreferences({ language }),
    onSuccess: (data) => {
      setAppLocale(data.language)
      queryClient.invalidateQueries({ queryKey: ['auth', 'me'] })
      queryClient.invalidateQueries({ queryKey: ['findings'] })
    },
  })

  const changeLanguage = (language: AppLocale) => {
    setAppLocale(language)
    mutation.mutate(language)
  }

  return {
    locale: getAppLocale(),
    changeLanguage,
    isSaving: mutation.isPending,
    error: mutation.error,
  }
}
