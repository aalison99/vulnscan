import type { LucideIcon } from 'lucide-react'

interface Props {
  label: string
  value: number | string
  icon: LucideIcon
  tone?: 'default' | 'red' | 'orange' | 'violet'
  hint?: string
}

const TONES = {
  default: 'bg-emerald-500/10 text-emerald-400',
  red: 'bg-red-500/10 text-red-400',
  orange: 'bg-orange-500/10 text-orange-400',
  violet: 'bg-violet-500/10 text-violet-400',
}

export default function KpiCard({ label, value, icon: Icon, tone = 'default', hint }: Props) {
  return (
    <div className="card flex items-center gap-4 p-5">
      <div className={`rounded-lg p-3 ${TONES[tone]}`}>
        <Icon className="h-5 w-5" />
      </div>
      <div className="min-w-0">
        <div className="text-2xl font-semibold text-white">{value}</div>
        <div className="text-sm text-slate-400">{label}</div>
        {hint && <div className="mt-0.5 truncate text-xs text-slate-500">{hint}</div>}
      </div>
    </div>
  )
}