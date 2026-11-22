import type { KeyboardEvent, ReactNode } from 'react'
import type { Misconfiguration, Secret, Vulnerability } from '../types'
import { formatLines } from '../lib'
import SeverityBadge from './SeverityBadge'

function Table({ head, children }: { head: string[]; children: ReactNode }) {
  return (
    <div className="overflow-x-auto">
      <table className="w-full min-w-[820px] text-left text-sm">
        <thead className="text-xs uppercase tracking-wide text-slate-500">
          <tr className="border-b border-ink-600/60">
            {head.map((h) => (
              <th key={h} className="px-4 py-3 font-medium">
                {h}
              </th>
            ))}
          </tr>
        </thead>
        <tbody className="divide-y divide-ink-600/40">{children}</tbody>
      </table>
    </div>
  )
}

function Row({ onSelect, children }: { onSelect: () => void; children: ReactNode }) {
  const onKey = (e: KeyboardEvent) => {
    if (e.key === 'Enter' || e.key === ' ') {
      e.preventDefault()
      onSelect()
    }
  }
  return (
    <tr
      tabIndex={0}
      onClick={onSelect}
      onKeyDown={onKey}
      className="cursor-pointer align-top hover:bg-ink-700/40 focus:bg-ink-700/40 focus:outline-none"
    >
      {children}
    </tr>
  )
}

const mono = 'px-4 py-3 font-mono text-xs text-slate-300 break-all'

export function VulnTable({
  items,
  onSelect,
}: {
  items: Vulnerability[]
  onSelect: (v: Vulnerability) => void
}) {
  return (
    <Table head={['Severity', 'CVE', 'Package', 'Installed', 'Fixed', 'CVSS', 'Title']}>
      {items.map((v, i) => (
        <Row key={`${v.id}-${v.pkg_name}-${v.installed_version}-${i}`} onSelect={() => onSelect(v)}>
          <td className="px-4 py-3">
            <SeverityBadge severity={v.severity} />
          </td>
          <td className={`${mono} whitespace-nowrap text-slate-100`}>{v.id}</td>
          <td className={mono}>{v.pkg_name}</td>
          <td className={mono}>{v.installed_version || '—'}</td>
          <td className={`${mono} ${v.fixed_version ? 'text-emerald-300' : 'text-slate-500'}`}>
            {v.fixed_version ?? 'no fix'}
          </td>
          <td className="px-4 py-3 font-mono text-xs text-slate-300">
            {v.cvss_score != null ? v.cvss_score.toFixed(1) : '—'}
          </td>
          <td className="max-w-[320px] px-4 py-3 text-slate-300">
            <div className="line-clamp-2">{v.title || v.description || '—'}</div>
          </td>
        </Row>
      ))}
    </Table>
  )
}

export function MisconfigTable({
  items,
  onSelect,
}: {
  items: Misconfiguration[]
  onSelect: (m: Misconfiguration) => void
}) {
  return (
    <Table head={['Severity', 'ID', 'Type', 'File', 'Lines', 'Title']}>
      {items.map((m, i) => (
        <Row key={`${m.id}-${m.target}-${m.start_line}-${i}`} onSelect={() => onSelect(m)}>
          <td className="px-4 py-3">
            <SeverityBadge severity={m.severity} />
          </td>
          <td className={`${mono} whitespace-nowrap text-slate-100`}>{m.avd_id || m.id}</td>
          <td className={mono}>{m.type || '—'}</td>
          <td className={mono}>{m.target || '—'}</td>
          <td className="px-4 py-3 font-mono text-xs text-slate-300">
            {formatLines(m.start_line, m.end_line)}
          </td>
          <td className="max-w-[320px] px-4 py-3 text-slate-300">
            <div className="line-clamp-2">{m.title || m.message || '—'}</div>
          </td>
        </Row>
      ))}
    </Table>
  )
}

export function SecretTable({
  items,
  onSelect,
}: {
  items: Secret[]
  onSelect: (s: Secret) => void
}) {
  return (
    <Table head={['Severity', 'Rule', 'Category', 'File', 'Lines', 'Title']}>
      {items.map((s, i) => (
        <Row key={`${s.rule_id}-${s.target}-${s.start_line}-${i}`} onSelect={() => onSelect(s)}>
          <td className="px-4 py-3">
            <SeverityBadge severity={s.severity} />
          </td>
          <td className={`${mono} whitespace-nowrap text-slate-100`}>{s.rule_id}</td>
          <td className={mono}>{s.category || '—'}</td>
          <td className={mono}>{s.target || '—'}</td>
          <td className="px-4 py-3 font-mono text-xs text-slate-300">
            {formatLines(s.start_line, s.end_line)}
          </td>
          <td className="max-w-[320px] px-4 py-3 text-slate-300">
            <div className="line-clamp-2">{s.title || '—'}</div>
          </td>
        </Row>
      ))}
    </Table>
  )
}