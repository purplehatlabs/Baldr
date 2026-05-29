import { LogOut } from 'lucide-react'
import { useTranslation } from 'react-i18next'
import { useAuth } from '@/hooks/useAuth'

export default function Header({ title }: { title: string }) {
  const { user, logout } = useAuth()
  const { t } = useTranslation()

  return (
    <header className="h-14 border-b border-gray-200 bg-white flex items-center justify-between px-6">
      <h1 className="font-semibold text-gray-900">{title}</h1>

      <div className="flex items-center gap-4">
        {user && (
          <div className="flex items-center gap-3">
            <img
              src={user.avatar_url || `https://ui-avatars.com/api/?name=${encodeURIComponent(user.name)}`}
              alt={user.name}
              className="w-8 h-8 rounded-full"
            />
            <div className="hidden sm:block">
              <p className="text-sm font-medium text-gray-900">{user.name}</p>
              <p className="text-xs text-gray-500">{user.email}</p>
            </div>
            <button
              onClick={() => logout()}
              className="p-1.5 rounded-lg text-gray-400 hover:text-gray-600 hover:bg-gray-100 transition-colors"
              title={t('header.logout')}
            >
              <LogOut className="w-4 h-4" />
            </button>
          </div>
        )}
      </div>
    </header>
  )
}
