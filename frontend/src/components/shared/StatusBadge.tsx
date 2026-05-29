import { useTranslation } from 'react-i18next'
import { cn } from '@/lib/utils'
import type { FindingStatus } from '@/api/findings'

const classNames: Record<FindingStatus, string> = {
  open: 'bg-red-50 text-red-600 ring-red-200',
  suppressed: 'bg-gray-100 text-gray-500 ring-gray-200',
  fixed: 'bg-green-50 text-green-600 ring-green-200',
}

export function StatusBadge({ status }: { status: FindingStatus }) {
  const { t } = useTranslation()
  const label = t(`shared.findingStatus.${status}`, { defaultValue: t('shared.findingStatus.open') })

  return (
    <span
      className={cn(
        'inline-flex items-center rounded-full px-2.5 py-1 text-xs font-medium ring-1 ring-inset',
        classNames[status] ?? classNames.open,
      )}
    >
      {label}
    </span>
  )
}
