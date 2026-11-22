import { CheckCircle2, Clock, Loader2, XCircle } from 'lucide-react'
import type { ScanStatus } from '../types'

const STYLES: Record<ScanStatus, string> = {
  queued: 'border-slate-500/30 bg-slate-500/10 text-slate-300',
  running: 'border-sky-500/30 bg-sky-500/10 text-sky-300',
  completed: 'border-emerald-500/30 bg-emerald-500/10 text-emerald-300',
  failed: 'border-red-500/30 bg-red-500/10 text-red-300',
}

export default function StatusBadge({ status }: { status: ScanStatus }) {
  const icon =
    status === 'running' ? (
      <Loader2 className="h-3 w-3 animate-spin" />
    ) : status === 'completed' ? (
      <CheckCircle2 className="h-3 w-3" />
    ) : status === 'failed' ? (
      <XCircle className="h-3 w-3" />
    ) : (
      <Clock className="h-3 w-3" />
    )
  return (
    <span
      className={`inline-flex items-center gap-1.5 rounded-full border px-2.5 py-0.5 text-xs font-medium capitalize ${STYLES[status]}`}
    >
      {icon}
      {status}
    </span>
  )
}