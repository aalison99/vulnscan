import { useCallback, useEffect, useMemo, useState } from 'react'
import { Link } from 'react-router-dom'
import { Activity, AlertOctagon, AlertTriangle, KeyRound, PlusCircle, ShieldCheck } from 'lucide-react'
import { api } from '../api'
import type { ScanSummary, SeverityCounts } from '../types'
import { isActive } from '../lib'
import KpiCard from '../components/KpiCard'
import ScansTable from '../components/ScansTable'
import SeverityChart from '../components/SeverityChart'

export default function Dashboard() {
  const [scans, setScans] = useState<ScanSummary[] | null>(null)
  const [error, setError] = useState<string | null>(null)

  const load = useCallback(async () => {
    try {
      setScans(await api.listScans())
      setError(null)
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Failed to load scans')
    }
  }, [])

  useEffect(() => {
    load()
  }, [load])

  const hasActive = scans?.some((s) => isActive(s.status)) ?? false

  // Live polling only while something is queued/running
  useEffect(() => {
    if (!hasActive) return
    const t = setInterval(load, 3000)
    return () => clearInterval(t)
  }, [hasActive, load])

  const totals = useMemo(() => {
    const sev: SeverityCounts = { critical: 0, high: 0, medium: 0, low: 0, unknown: 0 }
    let secrets = 0
    let misconfigs = 0
    for (const s of scans ?? []) {
      if (s.status !== 'completed') continue
      sev.critical += s.severity_counts.critical
      sev.high += s.severity_counts.high
      sev.medium += s.severity_counts.medium
      sev.low += s.severity_counts.low
      sev.unknown += s.severity_counts.unknown
      secrets += s.secret_count
      misconfigs += s.misconfig_count
    }
    return { sev, secrets, misconfigs }
  }, [scans])

  const onDelete = async (scan: ScanSummary) => {
    if (!window.confirm(`Delete scan of "${scan.target}"?`)) return
    try {
      await api.deleteScan(scan.id)
      await load()
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Failed to delete scan')
    }
  }

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h1 className="text-2xl font-semibold text-white">Security Overview</h1>
          <p className="mt-1 flex items-center gap-2 text-sm text-slate-400">
            Findings across all completed scans
            {hasActive && (
              <span className="inline-flex items-center gap-1.5 text-sky-300">
                <span className="h-2 w-2 animate-pulse rounded-full bg-sky-400" />
                Live
              </span>
            )}
          </p>
        </div>
        <Link to="/scan/new" className="btn-primary">
          <PlusCircle className="h-4 w-4" /> New Scan
        </Link>
      </div>

      {error && (
        <div className="rounded-lg border border-red-500/30 bg-red-500/10 px-4 py-3 text-sm text-red-300">
          {error}
        </div>
      )}

      <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
        <KpiCard label="Total Scans" value={scans?.length ?? '–'} icon={Activity} />
        <KpiCard label="Critical CVEs" value={totals.sev.critical} icon={AlertOctagon} tone="red" />
        <KpiCard label="High CVEs" value={totals.sev.high} icon={AlertTriangle} tone="orange" />
        <KpiCard
          label="Secrets / Misconfigs"
          value={totals.secrets + totals.misconfigs}
          icon={KeyRound}
          tone="violet"
          hint={`${totals.secrets} secrets · ${totals.misconfigs} misconfigs`}
        />
      </div>

      <div className="card p-5">
        <h2 className="mb-4 text-sm font-semibold uppercase tracking-wide text-slate-400">
          Severity Distribution
        </h2>
        <SeverityChart counts={totals.sev} />
      </div>

      <div className="card">
        <div className="flex items-center justify-between border-b border-ink-600/60 px-5 py-4">
          <h2 className="text-sm font-semibold uppercase tracking-wide text-slate-400">
            Recent Scans
          </h2>
        </div>
        {scans === null && !error ? (
          <div className="p-10 text-center text-sm text-slate-500">Loading…</div>
        ) : scans && scans.length === 0 ? (
          <div className="flex flex-col items-center gap-3 p-12 text-center">
            <ShieldCheck className="h-10 w-10 text-slate-600" />
            <p className="text-sm text-slate-400">No scans yet. Start your first scan.</p>
            <Link to="/scan/new" className="btn-primary">
              <PlusCircle className="h-4 w-4" /> New Scan
            </Link>
          </div>
        ) : (
          scans && <ScansTable scans={scans.slice(0, 20)} onDelete={onDelete} />
        )}
      </div>
    </div>
  )
}