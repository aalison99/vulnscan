import { useEffect } from 'react'
import { X } from 'lucide-react'
import type { AwsFinding, FindingStatus } from '../types'
import { FINDING_STATUSES } from '../types'
import { BUCKET_BADGE, BUCKET_HEX, EXPOSURE_LABEL } from '../lib'

interface Props {
  finding: AwsFinding | null
  onClose: () => void
  onStatus: (f: AwsFinding, s: FindingStatus) => void
}

const FACTORS: { key: 'base' | 'exploitability' | 'exposure' | 'context'; label: string; hint: string }[] = [
  { key: 'base', label: 'Base severity', hint: 'CIS / AWS guidance, 0-10 scaled to 0-1' },
  { key: 'exploitability', label: 'Exploitability', hint: 'How easy the issue is to abuse' },
  { key: 'exposure', label: 'Exposure', hint: 'Internet, cross-account or internal' },
  { key: 'context', label: 'Context', hint: 'Environment tag and data sensitivity' },
]

export default function AwsFindingDrawer({ finding, onClose, onStatus }: Props) {
  useEffect(() => {
    if (!finding) return
    const h = (e: KeyboardEvent) => e.key === 'Escape' && onClose()
    window.addEventListener('keydown', h)
    return () => window.removeEventListener('keydown', h)
  }, [finding, onClose])

  if (!finding) return null
  const f = finding
  const hex = BUCKET_HEX[f.risk_bucket]

  return (
    <div className="fixed inset-0 z-50 flex justify-end" role="dialog" aria-modal="true" aria-label="Finding detail">
      <button type="button" className="absolute inset-0 bg-black/60" onClick={onClose} aria-label="Close" />
      <aside className="relative h-full w-full max-w-xl space-y-6 overflow-y-auto border-l border-ink-600 bg-ink-900 p-6">
        <div className="flex items-start justify-between gap-4">
          <div className="min-w-0">
            <span className={`rounded-md border px-2 py-0.5 text-[11px] font-semibold uppercase ${BUCKET_BADGE[f.risk_bucket]}`}>
              {f.risk_bucket} risk
            </span>
            <h2 className="mt-2 text-lg font-semibold text-white">{f.title}</h2>
            <div className="mt-1 break-all font-mono text-xs text-slate-400">{f.resource_arn}</div>
          </div>
          <button type="button" onClick={onClose} className="rounded p-1 text-slate-400 hover:text-white" aria-label="Close panel">
            <X className="h-5 w-5" />
          </button>
        </div>

        <section>
          <div className="mb-2 flex items-baseline justify-between">
            <h3 className="text-xs font-medium uppercase tracking-wide text-slate-500">Why this score</h3>
            <span className="text-2xl font-semibold" style={{ color: hex }}>{f.risk_score}</span>
          </div>
          <p className="mb-3 text-xs text-slate-500">
            risk = 100 × base × exploitability × exposure × context. Each bar is a multiplier from 0 to 1.
          </p>
          <ul className="space-y-3">
            {FACTORS.map(({ key, label, hint }) => (
              <li key={key}>
                <div className="flex justify-between text-sm">
                  <span className="text-slate-200">{label}</span>
                  <span className="font-mono text-slate-300">{f.breakdown[key].toFixed(2)}</span>
                </div>
                <div className="mt-1 h-2 rounded-full bg-ink-700" role="img" aria-label={`${label} ${f.breakdown[key].toFixed(2)} of 1`}>
                  <div className="h-2 rounded-full" style={{ width: `${f.breakdown[key] * 100}%`, background: hex }} />
                </div>
                <div className="mt-0.5 text-xs text-slate-500">{hint}</div>
              </li>
            ))}
          </ul>
          <div className="mt-3 rounded-lg border border-ink-600 bg-ink-800 p-3 text-xs text-slate-400">
            Environment: <span className="text-slate-200">{f.environment}</span> · Exposure:{' '}
            <span className="text-slate-200">{EXPOSURE_LABEL[f.exposure]}</span> · Flat severity would be{' '}
            <span className="text-slate-200">{f.flat_severity}</span>
          </div>
        </section>

        <section>
          <h3 className="mb-1 text-xs font-medium uppercase tracking-wide text-slate-500">Description</h3>
          <p className="text-sm text-slate-200">{f.description}</p>
          <div className="mt-2 text-xs text-slate-500">
            CIS control {f.cis_id} · {f.category} · {f.region}
          </div>
        </section>

        <section>
          <h3 className="mb-1 text-xs font-medium uppercase tracking-wide text-slate-500">Evidence</h3>
          <pre className="overflow-x-auto rounded-lg bg-ink-800 p-3 font-mono text-xs text-slate-300">
            {JSON.stringify(f.evidence, null, 2)}
          </pre>
        </section>

        <section>
          <h3 className="mb-1 text-xs font-medium uppercase tracking-wide text-slate-500">Remediation</h3>
          <div className="whitespace-pre-wrap break-words rounded-lg border border-emerald-500/20 bg-emerald-500/5 p-3 font-mono text-xs text-emerald-100">
            {f.remediation}
          </div>
        </section>

        <section>
          <label className="mb-1 block text-xs font-medium uppercase tracking-wide text-slate-500" htmlFor="fstatus">
            Remediation status
          </label>
          <select id="fstatus" className="input" value={f.status} onChange={(e) => onStatus(f, e.target.value as FindingStatus)}>
            {FINDING_STATUSES.map((s) => (
              <option key={s} value={s}>{s}</option>
            ))}
          </select>
        </section>
      </aside>
    </div>
  )
}
