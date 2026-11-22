import type { ScanStatus, ScanType, Severity, SeverityCounts } from './types'

export const SEVERITY_ORDER: Severity[] = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN']

export const SEVERITY_HEX: Record<Severity, string> = {
  CRITICAL: '#ef4444',
  HIGH: '#f97316',
  MEDIUM: '#eab308',
  LOW: '#3b82f6',
  UNKNOWN: '#64748b',
}

export const SEVERITY_BADGE: Record<Severity, string> = {
  CRITICAL: 'border-red-500/30 bg-red-500/15 text-red-300',
  HIGH: 'border-orange-500/30 bg-orange-500/15 text-orange-300',
  MEDIUM: 'border-yellow-500/30 bg-yellow-500/15 text-yellow-300',
  LOW: 'border-blue-500/30 bg-blue-500/15 text-blue-300',
  UNKNOWN: 'border-slate-500/30 bg-slate-500/15 text-slate-300',
}

export const SCAN_TYPE_LABEL: Record<ScanType, string> = {
  image: 'Image',
  repo: 'Repository',
  fs: 'Archive',
}

export function countFor(counts: SeverityCounts, sev: Severity): number {
  return counts[sev.toLowerCase() as keyof SeverityCounts]
}

export const isActive = (s: ScanStatus) => s === 'queued' || s === 'running'

export function formatDate(iso: string | null): string {
  if (!iso) return '—'
  const d = new Date(iso)
  if (Number.isNaN(d.getTime())) return '—'
  return d.toLocaleString(undefined, {
    year: 'numeric',
    month: 'short',
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
  })
}

export function formatDuration(start: string | null, end: string | null): string {
  if (!start) return '—'
  const s = Date.parse(start)
  const e = end ? Date.parse(end) : Date.now()
  if (Number.isNaN(s) || Number.isNaN(e)) return '—'
  const secs = Math.max(0, Math.round((e - s) / 1000))
  if (secs < 60) return `${secs}s`
  const m = Math.floor(secs / 60)
  return `${m}m ${secs % 60}s`
}

/** Only allow http(s) links, so scan data can never inject javascript: URLs. */
export const isSafeUrl = (u: string) => /^https?:\/\//i.test(u)

export function formatLines(start: number | null, end: number | null): string {
  if (!start) return '—'
  return end && end !== start ? `${start}–${end}` : `${start}`
}