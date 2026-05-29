import { cn } from '@/lib/utils'

export function Spinner({ className }: { className?: string }) {
  return (
    <div className={cn('animate-spin rounded-full border-2 border-gray-200 border-t-brand-500', className)} />
  )
}

export function PageSpinner() {
  return (
    <div className="flex items-center justify-center py-24">
      <Spinner className="w-8 h-8" />
    </div>
  )
}
