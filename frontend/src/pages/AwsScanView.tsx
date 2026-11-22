import { useCallback, useEffect, useMemo, useState } from 'react'
import { AlertTriangle, ArrowLeftRight, Download, Search, Trash2 } from 'lucide-react'
import { api } from '../api'
import type { AwsFinding, AwsReport, FindingStatus, ScanDetail } from '../types'
import { FINDING_STATUSES } from '../types'
import { BUCKET_BADGE, BUCKET_HEX, BUCKET_ORDER, EXPOSURE_LABEL, SEVERITY_BADGE } from '../lib'
import AwsFindingDrawer from '../components/AwsFindingDrawer'
import ContextMatrix from '../components/ContextMatrix'

type Mode = 'risk' | 'flat'
const PAGE = 100

function uniq(items: AwsFinding[], pick: (f: AwsFinding) => string) {
  return [...new Set(items.map(pick))].sort()
}

export default function AwsScanView({ scan, onDelete }: { scan: ScanDetail; onDelete: () => void }) {
  const [findings, setFindings] = useState<AwsFinding[] | null>(null)
  const [report, setReport] = useState<AwsReport | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [mode, setMode] = useState<Mode>('risk')
  const [query, setQuery] = useState('')
  const [category, setCategory] = useState('')
  const [env, setEnv] = useState('')
  const [exposure, setExposure] = useState('')
  const [status, setStatus] = useState('')
  const [limit, setLimit] = useState(PAGE)
  const [selectedId, setSelectedId] = useState<string | null>(null)

  const completed = scan.status === 'completed'
  const load = useCallback(async () => {
    try {
      const [f, r] = await Promise.all([api.awsFindings(scan.id), api.awsReport(scan.id)])
      setFindings(f)
      setReport(r)
      setError(null)
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Failed to load findings')
    }
  }, [scan.id])

  useEffect(() => {
    if (completed) load()
  }, [completed, load])

  useEffect(() => setLimit(PAGE), [mode, query, category, env, exposure, status])

  // Risk rank is the API order. Flat rank sorts by base severity only (stable, so ties keep risk order).
  const riskRank = useMemo(() => new Map((findings ?? []).map((f, i) => [f.id, i + 1])), [findings])
  const flatRank = useMemo(() => {
    const sorted = [...(findings ?? [])].sort((a, b) => b.base_severity - a.base_severity)
    return new Map(sorted.map((f, i) => [f.id, i + 1]))
  }, [findings])

  const shown = useMemo(() => {
    const q = query.trim().toLowerCase()
    const rows = (findings ?? []).filter(
      (f) =>
        (!category || f.category === category) &&
        (!env || f.environment.split(' ')[0] === env) &&
        (!exposure || f.exposure === exposure) &&
        (!status || f.status === status) &&
        (!q || [f.title, f.resource_arn, f.rule_id, f.cis_id].some((x) => x.toLowerCase().includes(q))),
    )
    const rank = mode === 'risk' ? riskRank : flatRank
    return rows.sort((a, b) => rank.get(a.id)! - rank.get(b.id)!)
  }, [findings, query, category, env, exposure, status, mode, riskRank, flatRank])

  const setFindingStatus = async (f: AwsFinding, s: FindingStatus) => {
    const prev = f.status
    setFindings((cur) => cur && cur.map((x) => (x.id === f.id ? { ...x, status: s } : x)))
    try {
      await api.updateFinding(f.id, s)
    } catch (e) {
      setFindings((cur) => cur && cur.map((x) => (x.id === f.id ? { ...x, status: prev } : x)))
      setError(e instanceof Error ? e.message : 'Failed to update status')
    }
  }

  const selected = findings?.find((f) => f.id === selectedId) ?? null
  const counts = scan.severity_counts
  const top3 = (findings ?? []).slice(0, 3)

  if (!completed) return null

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap gap-2">
        <a href={api.awsCsvUrl(scan.id)} download className="btn-ghost">
          <Download className="h-4 w-4" /> Export CSV
        </a>
        <button type="button" onClick={onDelete} className="btn-danger">
          <Trash2 className="h-4 w-4" /> Delete
        </button>
      </div>

      {error && (
        <div role="alert" className="rounded-lg border border-red-500/30 bg-red-500/10 px-4 py-3 text-sm text-red-300">{error}</div>
      )}

      <div className="flex flex-wrap gap-2">
        {BUCKET_ORDER.map((b) => (
          <div key={b} className={`rounded-lg border px-4 py-2 ${BUCKET_BADGE[b]}`} title="Findings by context-aware risk bucket">
            <div className="text-xl font-semibold">{counts[b]}</div>
            <div className="text-[11px] font-semibold uppercase tracking-wide opacity-80">{b} risk</div>
          </div>
        ))}
        <div className="rounded-lg border border-ink-600 px-4 py-2">
          <div className="text-xl font-semibold text-white">{scan.misconfig_count}</div>
          <div className="text-[11px] font-semibold uppercase tracking-wide text-slate-400">Total findings</div>
        </div>
      </div>

      {report && report.not_assessed.length > 0 && (
        <div className="rounded-lg border border-amber-500/30 bg-amber-500/10 px-4 py-3 text-sm text-amber-200">
          <div className="mb-1 flex items-center gap-2 font-medium">
            <AlertTriangle className="h-4 w-4" /> {report.not_assessed.length} check(s) could not be assessed
          </div>
          <ul className="space-y-0.5 text-xs text-amber-100/80">
            {report.not_assessed.slice(0, 5).map((n, i) => (
              <li key={i} className="break-all font-mono">{n.service}: {n.message}</li>
            ))}
          </ul>
          <p className="mt-1 text-xs">These are not passes. Grant read access and rescan to cover them.</p>
        </div>
      )}

      <div className="card p-5">
        <h2 className="text-sm font-semibold text-white">Top risks</h2>
        {top3.length === 0 ? (
          <p className="mt-2 text-sm text-slate-500">No findings.</p>
        ) : (
          <ol className="mt-3 space-y-2">
            {top3.map((f) => (
              <li key={f.id}>
                <button type="button" onClick={() => setSelectedId(f.id)} className="flex w-full items-center gap-3 rounded-lg border border-ink-600 bg-ink-900 px-3 py-2 text-left hover:border-emerald-500/50">
                  <span className="w-10 font-mono text-lg font-semibold" style={{ color: BUCKET_HEX[f.risk_bucket] }}>{f.risk_score}</span>
                  <span className="min-w-0 flex-1">
                    <span className="block truncate text-sm text-slate-100">{f.title}</span>
                    <span className="block truncate font-mono text-xs text-slate-500">{f.resource_arn}</span>
                  </span>
                  <span className="hidden text-xs text-slate-400 sm:block">{f.environment} · {EXPOSURE_LABEL[f.exposure]}</span>
                </button>
              </li>
            ))}
          </ol>
        )}
      </div>

      {findings && <ContextMatrix findings={findings} />}

      <div className="card">
        <div className="flex flex-wrap items-center justify-between gap-3 border-b border-ink-600/60 p-4">
          <div>
            <h2 className="text-sm font-semibold text-white">Findings ranked by {mode === 'risk' ? 'context-aware risk' : 'flat severity'}</h2>
            <p className="text-xs text-slate-500">
              {mode === 'risk'
                ? 'Base severity weighted by exploitability, exposure and environment.'
                : 'Base severity only, the way a context-blind scanner orders them.'}
            </p>
          </div>
          <div className="flex gap-1 rounded-lg bg-ink-900 p-1" role="group" aria-label="Ranking mode">
            {(['risk', 'flat'] as Mode[]).map((m) => (
              <button
                key={m}
                type="button"
                aria-pressed={mode === m}
                onClick={() => setMode(m)}
                className={`flex items-center gap-1.5 rounded-md px-3 py-1.5 text-sm font-medium ${mode === m ? 'bg-ink-700 text-white' : 'text-slate-400 hover:text-slate-200'}`}
              >
                {m === 'risk' && <ArrowLeftRight className="h-3.5 w-3.5" />}
                {m === 'risk' ? 'Context-aware' : 'Flat severity'}
              </button>
            ))}
          </div>
        </div>

        <div className="flex flex-wrap items-center gap-3 border-b border-ink-600/60 p-4">
          <div className="relative min-w-[200px] flex-1">
            <Search className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-slate-500" />
            <input className="input pl-9" placeholder="Search title, resource, rule, CIS id…" value={query} onChange={(e) => setQuery(e.target.value)} aria-label="Search findings" />
          </div>
          <Select label="Category" value={category} onChange={setCategory} options={uniq(findings ?? [], (f) => f.category)} />
          <Select label="Environment" value={env} onChange={setEnv} options={uniq(findings ?? [], (f) => f.environment.split(' ')[0])} />
          <Select label="Exposure" value={exposure} onChange={setExposure} options={uniq(findings ?? [], (f) => f.exposure)} />
          <Select label="Status" value={status} onChange={setStatus} options={[...FINDING_STATUSES]} />
        </div>

        {findings === null ? (
          <div className="p-12 text-center text-sm text-slate-500">Loading findings…</div>
        ) : shown.length === 0 ? (
          <div className="p-12 text-center text-sm text-slate-500">No findings match the current filters.</div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full min-w-[860px] text-left text-sm">
              <thead className="text-xs uppercase tracking-wide text-slate-500">
                <tr>
                  <th className="px-4 py-3">Rank</th>
                  <th className="px-4 py-3">Risk</th>
                  <th className="px-4 py-3">Finding</th>
                  <th className="px-4 py-3">Env</th>
                  <th className="px-4 py-3">Exposure</th>
                  <th className="px-4 py-3">Flat</th>
                  <th className="px-4 py-3">Status</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-ink-600/40">
                {shown.slice(0, limit).map((f) => {
                  const r = riskRank.get(f.id)!
                  const fl = flatRank.get(f.id)!
                  const moved = fl - r
                  return (
                    <tr key={f.id} className="cursor-pointer hover:bg-ink-700/40" onClick={() => setSelectedId(f.id)}>
                      <td className="px-4 py-3 font-mono text-slate-300">
                        {mode === 'risk' ? r : fl}
                        {mode === 'risk' && moved !== 0 && (
                          <span className={`ml-1 text-[11px] ${moved > 0 ? 'text-emerald-400' : 'text-slate-500'}`} title="Positions gained over the flat-severity ranking">
                            {moved > 0 ? `▲${moved}` : `▼${-moved}`}
                          </span>
                        )}
                      </td>
                      <td className="px-4 py-3">
                        <div className="flex items-center gap-2">
                          <span className="w-10 font-mono font-semibold" style={{ color: BUCKET_HEX[f.risk_bucket] }}>{f.risk_score}</span>
                          <span className={`rounded-md border px-1.5 py-0.5 text-[10px] font-semibold uppercase ${BUCKET_BADGE[f.risk_bucket]}`}>{f.risk_bucket}</span>
                        </div>
                      </td>
                      <td className="max-w-md px-4 py-3">
                        <div className="truncate text-slate-100">{f.title}</div>
                        <div className="truncate font-mono text-xs text-slate-500">{f.resource_arn}</div>
                      </td>
                      <td className="px-4 py-3 text-slate-300">{f.environment}</td>
                      <td className="px-4 py-3 text-slate-300">{EXPOSURE_LABEL[f.exposure]}</td>
                      <td className="px-4 py-3">
                        <span className={`rounded-md border px-1.5 py-0.5 text-[10px] font-semibold uppercase ${SEVERITY_BADGE[f.flat_severity]}`}>{f.flat_severity}</span>
                      </td>
                      <td className="px-4 py-3" onClick={(e) => e.stopPropagation()}>
                        <select className="input py-1 text-xs" value={f.status} aria-label={`Status of ${f.title}`} onChange={(e) => setFindingStatus(f, e.target.value as FindingStatus)}>
                          {FINDING_STATUSES.map((s) => <option key={s} value={s}>{s}</option>)}
                        </select>
                      </td>
                    </tr>
                  )
                })}
              </tbody>
            </table>
          </div>
        )}

        <div className="flex items-center justify-between border-t border-ink-600/60 px-4 py-3 text-xs text-slate-500">
          <span>Showing {Math.min(limit, shown.length)} of {shown.length}</span>
          {shown.length > limit && (
            <button type="button" className="btn-ghost px-3 py-1.5 text-xs" onClick={() => setLimit((l) => l + PAGE)}>Show more</button>
          )}
        </div>
      </div>

      <AwsFindingDrawer finding={selected} onClose={() => setSelectedId(null)} onStatus={setFindingStatus} />
    </div>
  )
}

function Select({ label, value, onChange, options }: { label: string; value: string; onChange: (v: string) => void; options: string[] }) {
  return (
    <select className="input w-auto" value={value} onChange={(e) => onChange(e.target.value)} aria-label={label}>
      <option value="">{label}: all</option>
      {options.map((o) => <option key={o} value={o}>{o}</option>)}
    </select>
  )
}
