import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { useEffect } from 'react'
import { getMe, logout, type User } from '@/api/auth'
import { setAppLocale } from '@/i18n'
import { normalizeLocale } from '@/i18n/languages'

export function useAuth() {
  const queryClient = useQueryClient()

  const { data: user, isLoading, isError } = useQuery<User>({
    queryKey: ['auth', 'me'],
    queryFn: getMe,
    retry: false,
  })

  useEffect(() => {
    if (user?.language) {
      setAppLocale(normalizeLocale(user.language))
    }
  }, [user?.language])

  const logoutMutation = useMutation({
    mutationFn: logout,
    onSuccess: () => {
      queryClient.clear()
      window.location.href = '/login'
    },
  })

  return {
    user,
    isLoading,
    isAuthenticated: !!user && !isError,
    logout: logoutMutation.mutate,
  }
}
