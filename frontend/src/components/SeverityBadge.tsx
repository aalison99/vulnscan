import type { Severity } from '../types'
import { SEVERITY_BADGE } from '../lib'

export default function SeverityBadge({ severity }: { severity: Severity }) {
  return (
    <span
      className={`inline-flex items-center rounded-md border px-2 py-0.5 text-[11px] font-semibold uppercase tracking-wide ${SEVERITY_BADGE[severity]}`}
    >
      {severity}
    </span>
  )
}