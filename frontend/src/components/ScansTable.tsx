import { Trash2 } from 'lucide-react'
import { useNavigate } from 'react-router-dom'
import type { ScanSummary, Severity } from '../types'
import { SCAN_TYPE_LABEL, SEVERITY_BADGE, countFor, formatDate } from '../lib'
import StatusBadge from './StatusBadge'

const CHIP_SEVERITIES: Severity[] = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']

interface Props {
  scans: ScanSummary[]
  onDelete: (scan: ScanSummary) => void
}

export default function ScansTable({ scans, onDelete }: Props) {
  const navigate = useNavigate()

  return (
    <div className="overflow-x-auto">
      <table className="w-full min-w-[760px] text-left text-sm">
        <thead className="text-xs uppercase tracking-wide text-slate-500">
          <tr className="border-b border-ink-600/60">
            <th className="px-4 py-3 font-medium">Target</th>
            <th className="px-4 py-3 font-medium">Type</th>
            <th className="px-4 py-3 font-medium">Status</th>
            <th className="px-4 py-3 font-medium">Vulnerabilities</th>
            <th className="px-4 py-3 font-medium">Misconf.</th>
            <th className="px-4 py-3 font-medium">Secrets</th>
            <th className="px-4 py-3 font-medium">Started</th>
            <th className="px-4 py-3" />
          </tr>
        </thead>
        <tbody className="divide-y divide-ink-600/40">
          {scans.map((s) => {
            const done = s.status === 'completed'
            return (
              <tr
                key={s.id}
                onClick={() => navigate(`/scans/${s.id}`)}
                className="cursor-pointer hover:bg-ink-700/40"
              >
                <td className="max-w-[260px] px-4 py-3">
                  <div className="truncate font-mono text-slate-100" title={s.target}>
                    {s.target}
                  </div>
                </td>
                <td className="px-4 py-3 text-slate-400">{SCAN_TYPE_LABEL[s.scan_type]}</td>
                <td className="px-4 py-3">
                  <StatusBadge status={s.status} />
                </td>
                <td className="px-4 py-3">
                  {done ? (
                    s.vulnerability_count === 0 ? (
                      <span className="text-slate-500">None</span>
                    ) : (
                      <div className="flex flex-wrap gap-1">
                        {CHIP_SEVERITIES.map((sev) => {
                          const n = countFor(s.severity_counts, sev)
                          return n > 0 ? (
                            <span
                              key={sev}
                              title={sev}
                              className={`rounded border px-1.5 py-0.5 font-mono text-xs ${SEVERITY_BADGE[sev]}`}
                            >
                              {n}
                            </span>
                          ) : null
                        })}
                      </div>
                    )
                  ) : (
                    <span className="text-slate-600">—</span>
                  )}
                </td>
                <td className="px-4 py-3 font-mono text-slate-300">
                  {done ? s.misconfig_count : <span className="text-slate-600">—</span>}
                </td>
                <td className="px-4 py-3 font-mono text-slate-300">
                  {done ? s.secret_count : <span className="text-slate-600">—</span>}
                </td>
                <td className="whitespace-nowrap px-4 py-3 text-slate-400">
                  {formatDate(s.created_at)}
                </td>
                <td className="px-4 py-3 text-right">
                  <button
                    type="button"
                    title="Delete scan"
                    className="rounded p-1.5 text-slate-500 hover:bg-red-500/10 hover:text-red-400"
                    onClick={(e) => {
                      e.stopPropagation()
                      onDelete(s)
                    }}
                  >
                    <Trash2 className="h-4 w-4" />
                  </button>
                </td>
              </tr>
            )
          })}
        </tbody>
      </table>
    </div>
  )
}