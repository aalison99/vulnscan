import { useEffect, useState } from 'react'
import { NavLink, Navigate, Route, Routes } from 'react-router-dom'
import { LayoutDashboard, PlusCircle, ShieldAlert } from 'lucide-react'
import { api } from './api'
import type { Health } from './types'
import Dashboard from './pages/Dashboard'
import NewScan from './pages/NewScan'
import ScanDetail from './pages/ScanDetail'

function HealthBadge() {
  const [health, setHealth] = useState<Health | null>(null)
  const [failed, setFailed] = useState(false)

  useEffect(() => {
    let alive = true
    const check = () =>
      api
        .health()
        .then((h) => {
          if (alive) {
            setHealth(h)
            setFailed(false)
          }
        })
        .catch(() => alive && setFailed(true))
    check()
    const t = setInterval(check, 30_000)
    return () => {
      alive = false
      clearInterval(t)
    }
  }, [])

  const ok = !failed && health?.status === 'ok'
  const label = failed
    ? 'Backend unreachable'
    : !health
      ? 'Checking…'
      : ok
        ? 'All systems operational'
        : 'Scanner server unavailable'
  const dot = failed ? 'bg-red-500' : !health ? 'bg-slate-500' : ok ? 'bg-emerald-400' : 'bg-amber-400'

  return (
    <div className="border-t border-ink-600/60 p-4 text-xs text-slate-400">
      <div className="flex items-center gap-2">
        <span className={`h-2 w-2 rounded-full ${dot}`} />
        <span>{label}</span>
      </div>
      {health?.scanner.version && (
        <div className="mt-1 truncate font-mono text-slate-500" title={health.scanner.version}>
          {health.scanner.version}
        </div>
      )}
    </div>
  )
}

const linkClass = ({ isActive }: { isActive: boolean }) =>
  `flex items-center gap-3 rounded-lg px-3 py-2 text-sm font-medium transition-colors ${
    isActive
      ? 'bg-emerald-500/10 text-emerald-300'
      : 'text-slate-400 hover:bg-ink-700 hover:text-slate-200'
  }`

export default function App() {
  return (
    <div className="flex min-h-screen">
      <aside className="sticky top-0 hidden h-screen w-60 shrink-0 flex-col border-r border-ink-600/60 bg-ink-900 md:flex">
        <div className="flex items-center gap-2 px-5 py-5">
          <ShieldAlert className="h-6 w-6 text-emerald-400" />
          <span className="text-lg font-semibold tracking-tight text-white">VulnScan</span>
        </div>
        <nav className="flex-1 space-y-1 px-3">
          <NavLink to="/" end className={linkClass}>
            <LayoutDashboard className="h-4 w-4" /> Dashboard
          </NavLink>
          <NavLink to="/scan/new" className={linkClass}>
            <PlusCircle className="h-4 w-4" /> New Scan
          </NavLink>
        </nav>
        <HealthBadge />
      </aside>

      <div className="flex min-w-0 flex-1 flex-col">
        {/* Mobile top bar */}
        <header className="flex items-center justify-between border-b border-ink-600/60 bg-ink-900 px-4 py-3 md:hidden">
          <div className="flex items-center gap-2">
            <ShieldAlert className="h-5 w-5 text-emerald-400" />
            <span className="font-semibold text-white">VulnScan</span>
          </div>
          <nav className="flex gap-1">
            <NavLink to="/" end className={linkClass}>
              <LayoutDashboard className="h-4 w-4" />
            </NavLink>
            <NavLink to="/scan/new" className={linkClass}>
              <PlusCircle className="h-4 w-4" />
            </NavLink>
          </nav>
        </header>

        <main className="mx-auto w-full max-w-7xl flex-1 p-4 md:p-8">
          <Routes>
            <Route path="/" element={<Dashboard />} />
            <Route path="/scan/new" element={<NewScan />} />
            <Route path="/scans/:id" element={<ScanDetail />} />
            <Route path="*" element={<Navigate to="/" replace />} />
          </Routes>
        </main>
      </div>
    </div>
  )
}