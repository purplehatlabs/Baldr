import { clsx, type ClassValue } from 'clsx'
import { twMerge } from 'tailwind-merge'
import type { Severity } from '../api/findings'

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs))
}

const severityRank: Record<Severity, number> = {
  critical: 4,
  high: 3,
  medium: 2,
  low: 1,
  unknown: 0,
}

export function meetsMinSeverity(finding: Severity, min: Severity): boolean {
  return severityRank[finding] >= severityRank[min]
}
