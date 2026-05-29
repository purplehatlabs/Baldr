import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { useEffect } from 'react'
import { useNavigate } from 'react-router-dom'
import {
  getMe,
  getAuthTenants,
  switchTenant,
  logout,
  type User,
  type TenantSummary,
} from '@/api/auth'
import { setAppLocale } from '@/i18n'
import { normalizeLocale } from '@/i18n/languages'

export function useAuth() {
  const queryClient = useQueryClient()
  const navigate = useNavigate()

  const { data: user, isLoading, isError } = useQuery<User>({
    queryKey: ['auth', 'me'],
    queryFn: getMe,
    retry: false,
  })

  const { data: tenantsData, isLoading: tenantsLoading } = useQuery({
    queryKey: ['auth', 'tenants'],
    queryFn: getAuthTenants,
    enabled: !!user && !isError,
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

  const switchTenantMutation = useMutation({
    mutationFn: switchTenant,
    onSuccess: async () => {
      await queryClient.invalidateQueries({ queryKey: ['auth', 'me'] })
      await queryClient.invalidateQueries({ queryKey: ['auth', 'tenants'] })
      queryClient.removeQueries({ predicate: (q) => !q.queryKey[0]?.toString().startsWith('auth') })
      navigate('/overview')
    },
  })

  const tenants: TenantSummary[] = tenantsData?.tenants ?? []
  const activeTenant =
    tenants.find((t) => t.is_active) ??
    tenants.find((t) => t.tenant_id === tenantsData?.active_tenant_id)

  return {
    user,
    tenants,
    activeTenant,
    tenantsLoading,
    isLoading,
    isAuthenticated: !!user && !isError,
    logout: logoutMutation.mutate,
    switchTenant: switchTenantMutation.mutate,
    isSwitchingTenant: switchTenantMutation.isPending,
  }
}
