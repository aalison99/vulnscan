import type { ScannerName, Severity } from '../types'
import { ALL_SCANNERS, SELECTABLE_SEVERITIES } from '../types'
import { SEVERITY_BADGE } from '../lib'

const SCANNER_LABELS: Record<ScannerName, string> = {
  vuln: 'Vulnerabilities',
  secret: 'Secrets',
  misconfig: 'Misconfigurations',
}

interface Props {
  scanners: ScannerName[]
  severities: Severity[]
  onScanners: (v: ScannerName[]) => void
  onSeverities: (v: Severity[]) => void
}

function toggle<T>(list: T[], item: T): T[] {
  return list.includes(item) ? list.filter((x) => x !== item) : [...list, item]
}

export default function ScannerOptions({ scanners, severities, onScanners, onSeverities }: Props) {
  return (
    <div className="grid gap-6 sm:grid-cols-2">
      <fieldset>
        <legend className="mb-2 text-sm font-medium text-slate-300">Scanners</legend>
        <div className="space-y-2">
          {ALL_SCANNERS.map((s) => (
            <label key={s} className="flex cursor-pointer items-center gap-2 text-sm text-slate-300">
              <input
                type="checkbox"
                className="h-4 w-4 rounded border-ink-600 bg-ink-900 accent-emerald-500"
                checked={scanners.includes(s)}
                onChange={() => onScanners(toggle(scanners, s))}
              />
              {SCANNER_LABELS[s]}
            </label>
          ))}
        </div>
      </fieldset>

      <fieldset>
        <legend className="mb-2 text-sm font-medium text-slate-300">Severity filter</legend>
        <div className="space-y-2">
          {SELECTABLE_SEVERITIES.map((s) => (
            <label key={s} className="flex cursor-pointer items-center gap-2 text-sm">
              <input
                type="checkbox"
                className="h-4 w-4 rounded border-ink-600 bg-ink-900 accent-emerald-500"
                checked={severities.includes(s)}
                onChange={() => onSeverities(toggle(severities, s))}
              />
              <span
                className={`rounded-md border px-2 py-0.5 text-[11px] font-semibold uppercase tracking-wide ${SEVERITY_BADGE[s]}`}
              >
                {s}
              </span>
            </label>
          ))}
        </div>
      </fieldset>
    </div>
  )
}