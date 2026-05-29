import { useTranslation } from 'react-i18next'
import { ChevronDown } from 'lucide-react'
import { useAuth } from '@/hooks/useAuth'
import { cn } from '@/lib/utils'

export default function TenantSwitcher() {
  const { t } = useTranslation()
  const { tenants, activeTenant, switchTenant, isSwitchingTenant, tenantsLoading } = useAuth()

  if (tenantsLoading || tenants.length <= 1) {
    return null
  }

  return (
    <div className="relative">
      <label htmlFor="tenant-switcher" className="sr-only">
        {t('header.tenantSwitcher.label')}
      </label>
      <select
        id="tenant-switcher"
        value={activeTenant?.tenant_id ?? ''}
        disabled={isSwitchingTenant}
        onChange={(e) => {
          const nextId = e.target.value
          if (nextId && nextId !== activeTenant?.tenant_id) {
            switchTenant(nextId)
          }
        }}
        className={cn(
          'appearance-none rounded-lg border border-gray-200 bg-white pl-3 pr-8 py-1.5 text-sm text-gray-700',
          'hover:border-gray-300 focus:outline-none focus:ring-2 focus:ring-indigo-500 focus:border-indigo-500',
          isSwitchingTenant && 'opacity-60 cursor-wait',
        )}
        title={t('header.tenantSwitcher.label')}
      >
        {tenants.map((tenant) => (
          <option key={tenant.tenant_id} value={tenant.tenant_id}>
            {tenant.tenant_name}
          </option>
        ))}
      </select>
      <ChevronDown
        className="pointer-events-none absolute right-2 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-400"
        aria-hidden
      />
    </div>
  )
}
