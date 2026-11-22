import { useCallback, useEffect, useMemo, useState } from 'react'
import { Link, useNavigate, useParams } from 'react-router-dom'
import { ArrowLeft, Download, Loader2, Search, Trash2, XCircle } from 'lucide-react'
import { api } from '../api'
import type { ScanDetail as ScanDetailT, Severity } from '../types'
import { SELECTABLE_SEVERITIES } from '../types'
import {
  SCAN_TYPE_LABEL,
  SEVERITY_BADGE,
  SEVERITY_ORDER,
  countFor,
  formatDate,
  formatDuration,
  isActive,
} from '../lib'
import StatusBadge from '../components/StatusBadge'
import FindingDrawer from '../components/FindingDrawer'
import type { Selected } from '../components/FindingDrawer'
import { MisconfigTable, SecretTable, VulnTable } from '../components/FindingsTables'
import AwsScanView from './AwsScanView'

type Tab = 'vulns' | 'misconfigs' | 'secrets'

const PAGE = 100
const FILTER_SEVERITIES: Severity[] = [...SELECTABLE_SEVERITIES, 'UNKNOWN']

const hit = (fields: (string | null)[], q: string) =>
  !q || fields.some((f) => (f ?? '').toLowerCase().includes(q))

export default function ScanDetail() {
  const { id } = useParams<{ id: string }>()
  const navigate = useNavigate()

  const [scan, setScan] = useState<ScanDetailT | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [tab, setTab] = useState<Tab>('vulns')
  const [query, setQuery] = useState('')
  const [sevFilter, setSevFilter] = useState<Severity[]>([])
  const [limit, setLimit] = useState(PAGE)
  const [selected, setSelected] = useState<Selected | null>(null)

  const load = useCallback(async () => {
    if (!id) return
    try {
      setScan(await api.getScan(id))
      setError(null)
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Failed to load scan')
    }
  }, [id])

  useEffect(() => {
    setScan(null)
    setTab('vulns')
    setSelected(null)
    load()
  }, [load])

  const active = scan ? isActive(scan.status) : false
  useEffect(() => {
    if (!active) return
    const t = setInterval(load, 2000)
    return () => clearInterval(t)
  }, [active, load])

  const q = query.trim().toLowerCase()

  useEffect(() => {
    setLimit(PAGE)
  }, [tab, q, sevFilter, id])

  const sevOk = useCallback(
    (s: Severity) => sevFilter.length === 0 || sevFilter.includes(s),
    [sevFilter],
  )

  const vulns = useMemo(
    () =>
      (scan?.vulnerabilities ?? []).filter(
        (v) => sevOk(v.severity) && hit([v.id, v.pkg_name, v.title, v.target], q),
      ),
    [scan, q, sevOk],
  )
  const misconfigs = useMemo(
    () =>
      (scan?.misconfigurations ?? []).filter(
        (m) => sevOk(m.severity) && hit([m.id, m.avd_id, m.title, m.message, m.target], q),
      ),
    [scan, q, sevOk],
  )
  const secrets = useMemo(
    () =>
      (scan?.secrets ?? []).filter(
        (s) => sevOk(s.severity) && hit([s.rule_id, s.title, s.category, s.target], q),
      ),
    [scan, q, sevOk],
  )

  const onDelete = async () => {
    if (!scan || !window.confirm(`Delete scan of "${scan.target}"?`)) return
    try {
      await api.deleteScan(scan.id)
      navigate('/')
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Failed to delete scan')
    }
  }

  const toggleSev = (s: Severity) =>
    setSevFilter((cur) => (cur.includes(s) ? cur.filter((x) => x !== s) : [...cur, s]))

  const back = (
    <Link to="/" className="inline-flex items-center gap-1.5 text-sm text-slate-400 hover:text-white">
      <ArrowLeft className="h-4 w-4" /> Dashboard
    </Link>
  )

  if (!scan) {
    return (
      <div className="space-y-4">
        {back}
        {error ? (
          <div className="rounded-lg border border-red-500/30 bg-red-500/10 px-4 py-3 text-sm text-red-300">
            {error}
          </div>
        ) : (
          <div className="p-10 text-center text-sm text-slate-500">Loading…</div>
        )}
      </div>
    )
  }

  if (scan.scan_type === 'aws') {
    return (
      <div className="space-y-6">
        {back}
        <div>
          <div className="flex flex-wrap items-center gap-3">
            <h1 className="break-all font-mono text-xl font-semibold text-white">{scan.target}</h1>
            <StatusBadge status={scan.status} />
          </div>
          <div className="mt-2 flex flex-wrap gap-x-5 gap-y-1 text-sm text-slate-400">
            <span>{SCAN_TYPE_LABEL[scan.scan_type]}</span>
            <span>Started {formatDate(scan.created_at)}</span>
            <span>Duration {formatDuration(scan.started_at, scan.finished_at)}</span>
          </div>
        </div>
        {error && (
          <div className="rounded-lg border border-red-500/30 bg-red-500/10 px-4 py-3 text-sm text-red-300">{error}</div>
        )}
        {active && (
          <div className="card flex flex-col items-center gap-3 p-12 text-center">
            <Loader2 className="h-8 w-8 animate-spin text-sky-400" />
            <p className="text-sm text-slate-300">Scanning AWS account (read-only)…</p>
          </div>
        )}
        {scan.status === 'failed' && (
          <div className="card border-red-500/30 p-6">
            <div className="mb-3 flex items-center gap-2 text-red-300">
              <XCircle className="h-5 w-5" />
              <span className="font-medium">Scan failed</span>
            </div>
            <pre className="overflow-x-auto whitespace-pre-wrap rounded-lg bg-ink-900 p-4 font-mono text-xs text-slate-300">
              {scan.error || 'Unknown error'}
            </pre>
            <button type="button" onClick={onDelete} className="btn-danger mt-4">
              <Trash2 className="h-4 w-4" /> Delete
            </button>
          </div>
        )}
        <AwsScanView scan={scan} onDelete={onDelete} />
      </div>
    )
  }

  const tabs: { key: Tab; label: string; count: number }[] = [
    { key: 'vulns', label: 'Vulnerabilities', count: scan.vulnerabilities.length },
    { key: 'misconfigs', label: 'Misconfigurations', count: scan.misconfigurations.length },
    { key: 'secrets', label: 'Exposed Secrets', count: scan.secrets.length },
  ]
  const filtered = tab === 'vulns' ? vulns : tab === 'misconfigs' ? misconfigs : secrets

  return (
    <div className="space-y-6">
      {back}

      <div className="flex flex-wrap items-start justify-between gap-4">
        <div className="min-w-0">
          <div className="flex flex-wrap items-center gap-3">
            <h1 className="break-all font-mono text-xl font-semibold text-white">{scan.target}</h1>
            <StatusBadge status={scan.status} />
          </div>
          <div className="mt-2 flex flex-wrap gap-x-5 gap-y-1 text-sm text-slate-400">
            <span>{SCAN_TYPE_LABEL[scan.scan_type]}</span>
            {scan.os && <span>OS: {scan.os}</span>}
            <span>Started {formatDate(scan.created_at)}</span>
            <span>Duration {formatDuration(scan.started_at, scan.finished_at)}</span>
          </div>
        </div>

        <div className="flex flex-wrap gap-2">
          {scan.status === 'completed' && (
            <>
              <a href={api.exportUrl(scan.id, 'json')} download className="btn-ghost">
                <Download className="h-4 w-4" /> Export JSON
              </a>
              <a href={api.exportUrl(scan.id, 'csv')} download className="btn-ghost">
                <Download className="h-4 w-4" /> Export CSV
              </a>
            </>
          )}
          <button type="button" onClick={onDelete} className="btn-danger">
            <Trash2 className="h-4 w-4" /> Delete
          </button>
        </div>
      </div>

      {error && (
        <div className="rounded-lg border border-red-500/30 bg-red-500/10 px-4 py-3 text-sm text-red-300">
          {error}
        </div>
      )}

      {active && (
        <div className="card flex flex-col items-center gap-3 p-12 text-center">
          <Loader2 className="h-8 w-8 animate-spin text-sky-400" />
          <p className="text-sm text-slate-300">
            {scan.status === 'queued' ? 'Waiting for a free scan slot…' : 'Scan in progress…'}
          </p>
          <p className="text-xs text-slate-500">
            The first scan may take a few minutes while databases are downloaded.
          </p>
        </div>
      )}

      {scan.status === 'failed' && (
        <div className="card border-red-500/30 p-6">
          <div className="mb-3 flex items-center gap-2 text-red-300">
            <XCircle className="h-5 w-5" />
            <span className="font-medium">Scan failed</span>
          </div>
          <pre className="overflow-x-auto whitespace-pre-wrap rounded-lg bg-ink-900 p-4 font-mono text-xs text-slate-300">
            {scan.error || 'Unknown error'}
          </pre>
        </div>
      )}

      {scan.status === 'completed' && (
        <>
          <div className="flex flex-wrap gap-2">
            {SEVERITY_ORDER.map((s) => {
              const n = countFor(scan.severity_counts, s)
              if (s === 'UNKNOWN' && n === 0) return null
              return (
                <div
                  key={s}
                  className={`rounded-lg border px-4 py-2 ${SEVERITY_BADGE[s]}`}
                  title="Vulnerability count"
                >
                  <div className="text-xl font-semibold">{n}</div>
                  <div className="text-[11px] font-semibold uppercase tracking-wide opacity-80">
                    {s}
                  </div>
                </div>
              )
            })}
          </div>

          <div className="card">
            <div className="flex gap-1 overflow-x-auto border-b border-ink-600/60 px-3 pt-3">
              {tabs.map((t) => (
                <button
                  key={t.key}
                  type="button"
                  onClick={() => setTab(t.key)}
                  className={`whitespace-nowrap rounded-t-lg border-b-2 px-4 py-2.5 text-sm font-medium transition-colors ${
                    tab === t.key
                      ? 'border-emerald-400 text-white'
                      : 'border-transparent text-slate-400 hover:text-slate-200'
                  }`}
                >
                  {t.label}
                  <span className="ml-2 rounded-full bg-ink-700 px-2 py-0.5 font-mono text-xs text-slate-300">
                    {t.count}
                  </span>
                </button>
              ))}
            </div>

            <div className="flex flex-wrap items-center gap-3 border-b border-ink-600/60 p-4">
              <div className="relative min-w-[220px] flex-1">
                <Search className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-slate-500" />
                <input
                  className="input pl-9"
                  placeholder="Search ID, package, file, title…"
                  value={query}
                  onChange={(e) => setQuery(e.target.value)}
                />
              </div>
              <div className="flex flex-wrap gap-1.5">
                {FILTER_SEVERITIES.map((s) => {
                  const on = sevFilter.includes(s)
                  return (
                    <button
                      key={s}
                      type="button"
                      onClick={() => toggleSev(s)}
                      className={`rounded-md border px-2.5 py-1 text-[11px] font-semibold uppercase tracking-wide transition-opacity ${SEVERITY_BADGE[s]} ${
                        on || sevFilter.length === 0 ? 'opacity-100' : 'opacity-40'
                      }`}
                    >
                      {s}
                    </button>
                  )
                })}
              </div>
            </div>

            {filtered.length === 0 ? (
              <div className="p-12 text-center text-sm text-slate-500">
                {tabs.find((t) => t.key === tab)!.count === 0
                  ? 'Nothing found in this category.'
                  : 'No findings match the current filters.'}
              </div>
            ) : (
              <>
                {tab === 'vulns' && (
                  <VulnTable
                    items={vulns.slice(0, limit)}
                    onSelect={(item) => setSelected({ kind: 'vuln', item })}
                  />
                )}
                {tab === 'misconfigs' && (
                  <MisconfigTable
                    items={misconfigs.slice(0, limit)}
                    onSelect={(item) => setSelected({ kind: 'misconfig', item })}
                  />
                )}
                {tab === 'secrets' && (
                  <SecretTable
                    items={secrets.slice(0, limit)}
                    onSelect={(item) => setSelected({ kind: 'secret', item })}
                  />
                )}
                <div className="flex items-center justify-between border-t border-ink-600/60 px-4 py-3 text-xs text-slate-500">
                  <span>
                    Showing {Math.min(limit, filtered.length)} of {filtered.length}
                  </span>
                  {filtered.length > limit && (
                    <button
                      type="button"
                      className="btn-ghost px-3 py-1.5 text-xs"
                      onClick={() => setLimit((l) => l + PAGE)}
                    >
                      Show more
                    </button>
                  )}
                </div>
              </>
            )}
          </div>
        </>
      )}

      <FindingDrawer selected={selected} onClose={() => setSelected(null)} />
    </div>
  )
}