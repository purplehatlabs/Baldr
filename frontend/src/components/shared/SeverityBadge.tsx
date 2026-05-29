import { useTranslation } from 'react-i18next'
import { cn } from '@/lib/utils'
import type { Severity } from '@/api/findings'

const classNames: Record<Severity, string> = {
  critical: 'bg-red-100 text-red-700 ring-red-200',
  high: 'bg-orange-100 text-orange-700 ring-orange-200',
  medium: 'bg-yellow-100 text-yellow-700 ring-yellow-200',
  low: 'bg-blue-100 text-blue-700 ring-blue-200',
  unknown: 'bg-gray-100 text-gray-600 ring-gray-200',
}

interface Props {
  severity: Severity
  size?: 'sm' | 'md'
}

export function SeverityBadge({ severity, size = 'md' }: Props) {
  const { t } = useTranslation()
  const label = t(`shared.severity.${severity}`, { defaultValue: t('shared.severity.unknown') })
  const className = classNames[severity] ?? classNames.unknown

  return (
    <span
      className={cn(
        'inline-flex items-center rounded-full font-medium ring-1 ring-inset',
        size === 'sm' ? 'px-2 py-0.5 text-xs' : 'px-2.5 py-1 text-xs',
        className,
      )}
    >
      {label}
    </span>
  )
}

export const severityOrder: Record<Severity, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  unknown: 4,
}

export const severityColor: Record<Severity, string> = {
  critical: '#ef4444',
  high: '#f97316',
  medium: '#eab308',
  low: '#3b82f6',
  unknown: '#9ca3af',
}
