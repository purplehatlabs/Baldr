import { useEffect } from 'react'
import { useMutation, useQueryClient } from '@tanstack/react-query'
import { useTranslation } from 'react-i18next'
import { Navigate, useNavigate, useParams } from 'react-router-dom'
import { acceptInvite } from '@/api/invites'
import { PageSpinner } from '@/components/shared/Spinner'
import { AlertCircle, CheckCircle } from 'lucide-react'
import { useAuth } from '@/hooks/useAuth'
import { buildLoginPath } from '@/lib/postLoginRedirect'

export default function AcceptInvitePage() {
  const { t } = useTranslation()
  const navigate = useNavigate()
  const queryClient = useQueryClient()
  const { token = '' } = useParams<{ token: string }>()
  const { isAuthenticated, isLoading } = useAuth()

  const mutation = useMutation({
    mutationFn: () => acceptInvite(token),
    onSuccess: async () => {
      await queryClient.invalidateQueries({ queryKey: ['auth', 'me'] })
      await queryClient.invalidateQueries({ queryKey: ['auth', 'tenants'] })
      queryClient.removeQueries({ predicate: (q) => !q.queryKey[0]?.toString().startsWith('auth') })
      navigate('/overview')
    },
  })

  useEffect(() => {
    if (token && isAuthenticated && mutation.isIdle) {
      mutation.mutate()
    }
  }, [token, isAuthenticated, mutation])

  if (!token) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-gray-50 px-4">
        <p className="text-sm text-red-600">{t('invite.invalidLink')}</p>
      </div>
    )
  }

  if (isLoading) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-gray-50">
        <PageSpinner />
      </div>
    )
  }

  if (!isAuthenticated) {
    return <Navigate to={buildLoginPath(`/invite/${token}`)} replace />
  }

  if (mutation.isPending || mutation.isIdle) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-gray-50">
        <PageSpinner />
      </div>
    )
  }

  if (mutation.isSuccess) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-gray-50 px-4">
        <p className="text-sm text-green-600 flex items-center gap-2">
          <CheckCircle className="w-4 h-4" /> {t('invite.acceptSuccess')}
        </p>
      </div>
    )
  }

  const msg =
    (mutation.error as { response?: { data?: { error?: string } } })?.response?.data?.error ??
    t('invite.acceptFailed')
  return (
    <div className="min-h-screen flex items-center justify-center bg-gray-50 px-4">
      <p className="text-sm text-red-600 flex items-center gap-2">
        <AlertCircle className="w-4 h-4" /> {msg}
      </p>
    </div>
  )
}
