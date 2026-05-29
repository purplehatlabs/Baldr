import { useTranslation } from 'react-i18next'
import { Clock, Loader, CheckCircle, XCircle, ListOrdered } from 'lucide-react'
import { cn } from '@/lib/utils'
import { getAppLocale } from '@/i18n'
import { formatDateTime } from '@/lib/locale'
import type { ScanJob } from '@/api/repos'
import type { ScanJobStatus } from '@/api/scanJobs'

type DisplayStatus = ScanJobStatus | 'never'

const iconByStatus: Record<DisplayStatus, typeof Clock> = {
  never: Clock,
  pending: ListOrdered,
  running: Loader,
  completed: CheckCircle,
  failed: XCircle,
}

const classNameByStatus: Record<DisplayStatus, string> = {
  never: 'text-gray-400',
  pending: 'text-amber-600 bg-amber-50 ring-1 ring-amber-200',
  running: 'text-blue-600 bg-blue-50 ring-1 ring-blue-200',
  completed: 'text-green-600',
  failed: 'text-red-600 bg-red-50 ring-1 ring-red-200',
}

export function resolveScanDisplayStatus(
  latestStatus?: ScanJobStatus | null,
  lastScannedAt?: string | null,
): DisplayStatus {
  if (latestStatus) return latestStatus
  if (lastScannedAt) return 'completed'
  return 'never'
}

export default function ScanStatusBadge({
  status,
  lastScannedAt,
  compact = false,
}: {
  status?: ScanJobStatus | null
  lastScannedAt?: string | null
  compact?: boolean
}) {
  const { t } = useTranslation()
  const display = resolveScanDisplayStatus(status, lastScannedAt)
  const Icon = iconByStatus[display]
  const className = classNameByStatus[display]
  const label = t(`shared.scanStatus.${display}`)
  const isAnimated = display === 'running'
  const locale = getAppLocale()

  if (display === 'completed' && lastScannedAt) {
    const date = new Date(lastScannedAt)
    const diff = Date.now() - date.getTime()
    const hours = diff / 3_600_000
    const timeLabel =
      hours < 24
        ? date.toLocaleTimeString(locale === 'pt-BR' ? 'pt-BR' : 'en-US', {
            hour: '2-digit',
            minute: '2-digit',
          })
        : formatDateTime(date, locale)

    return (
      <span className={cn('inline-flex items-center gap-1.5 text-xs', className)}>
        <Icon className="w-3.5 h-3.5" />
        {compact ? timeLabel : `${label} · ${timeLabel}`}
      </span>
    )
  }

  if (display === 'never') {
    return (
      <span className={cn('inline-flex items-center gap-1.5 text-xs', className)}>
        <Icon className="w-3.5 h-3.5" />
        {label}
      </span>
    )
  }

  return (
    <span
      className={cn(
        'inline-flex items-center gap-1.5 text-xs font-medium rounded-full px-2 py-0.5',
        className,
      )}
    >
      <Icon className={cn('w-3.5 h-3.5', isAnimated && 'animate-spin')} />
      {label}
    </span>
  )
}

export function useScanTriggeredByLabel() {
  const { t } = useTranslation()

  return (trigger: ScanJob['triggered_by']): string => {
    switch (trigger) {
      case 'manual':
        return t('shared.scanTrigger.manual')
      case 'scheduled':
        return t('shared.scanTrigger.scheduled')
      case 'webhook':
        return t('shared.scanTrigger.webhook')
      default:
        return trigger
    }
  }
}

/** @deprecated Use useScanTriggeredByLabel() inside React components */
export function triggeredByLabel(trigger: ScanJob['triggered_by']): string {
  switch (trigger) {
    case 'manual':
      return 'Manual'
    case 'scheduled':
      return 'Scheduled'
    case 'webhook':
      return 'Webhook'
    default:
      return trigger
  }
}
