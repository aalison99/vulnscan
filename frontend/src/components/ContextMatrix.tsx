import type { AwsFinding } from '../types'
import { EXPOSURE_LABEL } from '../lib'

const ENVS = ['prod', 'staging', 'test', 'untagged']
const EXPOSURES = ['internet', 'cross_account', 'internal']

/** Exposure x environment grid. Cell shade scales with the count; the number is always printed. */
export default function ContextMatrix({ findings }: { findings: AwsFinding[] }) {
  const cell = (env: string, exp: string) =>
    findings.filter((f) => f.environment.split(' ')[0] === env && f.exposure === exp)
  const max = Math.max(1, ...ENVS.flatMap((e) => EXPOSURES.map((x) => cell(e, x).length)))

  return (
    <div className="card p-5">
      <h2 className="text-sm font-semibold text-white">Context view: exposure × environment</h2>
      <p className="mb-4 mt-1 text-xs text-slate-500">
        The top-left corner (internet-exposed, production) is where context-aware scoring puts the most weight.
      </p>
      <div className="overflow-x-auto">
        <table className="w-full min-w-[420px] border-separate border-spacing-1 text-center text-sm">
          <thead>
            <tr>
              <th />
              {ENVS.map((e) => (
                <th key={e} className="pb-1 text-xs font-medium uppercase tracking-wide text-slate-400">{e}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {EXPOSURES.map((x) => (
              <tr key={x}>
                <th className="pr-2 text-right text-xs font-medium text-slate-400">{EXPOSURE_LABEL[x]}</th>
                {ENVS.map((e) => {
                  const items = cell(e, x)
                  const avg = items.length ? items.reduce((a, f) => a + f.risk_score, 0) / items.length : 0
                  return (
                    <td
                      key={e}
                      className="rounded-md py-3"
                      style={{ background: `rgba(16,185,129,${0.08 + 0.5 * (items.length / max)})` }}
                      title={`${items.length} findings, average risk ${avg.toFixed(0)}`}
                    >
                      <div className="text-lg font-semibold text-white">{items.length}</div>
                      <div className="text-[11px] text-slate-300">{items.length ? `avg ${avg.toFixed(0)}` : '—'}</div>
                    </td>
                  )
                })}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  )
}
