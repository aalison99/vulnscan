import { useEffect } from 'react'
import type { ReactNode } from 'react'
import { ExternalLink, X } from 'lucide-react'
import type { Misconfiguration, Secret, Vulnerability } from '../types'
import { formatLines, isSafeUrl } from '../lib'
import SeverityBadge from './SeverityBadge'

export type Selected =
  | { kind: 'vuln'; item: Vulnerability }
  | { kind: 'misconfig'; item: Misconfiguration }
  | { kind: 'secret'; item: Secret }

function Field({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div>
      <div className="mb-1 text-xs font-medium uppercase tracking-wide text-slate-500">{label}</div>
      <div className="break-words text-sm text-slate-200">{children}</div>
    </div>
  )
}

function Mono({ children }: { children: ReactNode }) {
  return <span className="break-all font-mono text-xs">{children}</span>
}

function Text({ children }: { children: string }) {
  return children ? (
    <p className="whitespace-pre-wrap leading-relaxed">{children}</p>
  ) : (
    <span className="text-slate-500">Not provided</span>
  )
}

function Remediation({ children }: { children: string }) {
  return (
    <div className="rounded-lg border border-emerald-500/20 bg-emerald-500/5 p-3 text-sm text-emerald-100">
      {children || 'No remediation guidance available.'}
    </div>
  )
}

function References({ urls }: { urls: string[] }) {
  const safe = urls.filter(isSafeUrl)
  if (safe.length === 0) return <span className="text-slate-500">None</span>
  return (
    <ul className="space-y-1">
      {safe.map((u) => (
        <li key={u}>
          <a
            href={u}
            target="_blank"
            rel="noopener noreferrer"
            className="inline-flex items-start gap-1.5 break-all text-xs text-sky-400 hover:underline"
          >
            <ExternalLink className="mt-0.5 h-3 w-3 shrink-0" />
            {u}
          </a>
        </li>
      ))}
    </ul>
  )
}

function Body({ sel }: { sel: Selected }) {
  if (sel.kind === 'vuln') {
    const v = sel.item
    return (
      <>
        <Field label="Package">
          <Mono>
            {v.pkg_name} {v.installed_version}
          </Mono>
        </Field>
        <div className="grid grid-cols-2 gap-4">
          <Field label="Installed version">
            <Mono>{v.installed_version || '—'}</Mono>
          </Field>
          <Field label="Fixed version">
            <Mono>{v.fixed_version ?? 'No fix available'}</Mono>
          </Field>
          <Field label="CVSS">
            {v.cvss_score != null ? (
              <>
                <span className="font-semibold">{v.cvss_score.toFixed(1)}</span>
                {v.cvss_vector && (
                  <div className="mt-1">
                    <Mono>{v.cvss_vector}</Mono>
                  </div>
                )}
              </>
            ) : (
              '—'
            )}
          </Field>
          <Field label="Published">{v.published_date?.slice(0, 10) ?? '—'}</Field>
        </div>
        <Field label="Location">
          <Mono>{v.target || '—'}</Mono>
        </Field>
        <Field label="Description">
          <Text>{v.description}</Text>
        </Field>
        <Field label="Remediation">
          <Remediation>{v.remediation}</Remediation>
        </Field>
        <Field label="References">
          <References urls={v.references} />
        </Field>
      </>
    )
  }

  if (sel.kind === 'misconfig') {
    const m = sel.item
    return (
      <>
        <div className="grid grid-cols-2 gap-4">
          <Field label="Type">{m.type || '—'}</Field>
          <Field label="Lines">
            <Mono>{formatLines(m.start_line, m.end_line)}</Mono>
          </Field>
          <Field label="Provider">{m.provider || '—'}</Field>
          <Field label="Service">{m.service || '—'}</Field>
        </div>
        <Field label="File">
          <Mono>{m.target || '—'}</Mono>
        </Field>
        <Field label="Finding">
          <Text>{m.message}</Text>
        </Field>
        <Field label="Description">
          <Text>{m.description}</Text>
        </Field>
        <Field label="Remediation">
          <Remediation>{m.remediation}</Remediation>
        </Field>
        <Field label="References">
          <References urls={m.references} />
        </Field>
      </>
    )
  }

  const s = sel.item
  return (
    <>
      <div className="grid grid-cols-2 gap-4">
        <Field label="Category">{s.category || '—'}</Field>
        <Field label="Lines">
          <Mono>{formatLines(s.start_line, s.end_line)}</Mono>
        </Field>
      </div>
      <Field label="File">
        <Mono>{s.target || '—'}</Mono>
      </Field>
      <Field label="Match">
        <pre className="overflow-x-auto rounded-lg border border-ink-600 bg-ink-900 p-3 font-mono text-xs text-amber-200">
          {s.match || '—'}
        </pre>
      </Field>
      <Field label="Remediation">
        <Remediation>{s.remediation}</Remediation>
      </Field>
    </>
  )
}

function heading(sel: Selected): { id: string; title: string } {
  switch (sel.kind) {
    case 'vuln':
      return { id: sel.item.id, title: sel.item.title }
    case 'misconfig':
      return { id: sel.item.avd_id || sel.item.id, title: sel.item.title }
    case 'secret':
      return { id: sel.item.rule_id, title: sel.item.title }
  }
}

export default function FindingDrawer({
  selected,
  onClose,
}: {
  selected: Selected | null
  onClose: () => void
}) {
  useEffect(() => {
    if (!selected) return
    const onKey = (e: KeyboardEvent) => e.key === 'Escape' && onClose()
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [selected, onClose])

  if (!selected) return null
  const { id, title } = heading(selected)

  return (
    <div className="fixed inset-0 z-50 flex justify-end">
      <div className="absolute inset-0 bg-black/60" onClick={onClose} />
      <aside
        role="dialog"
        aria-modal="true"
        className="relative flex h-full w-full max-w-xl flex-col border-l border-ink-600 bg-ink-800 shadow-2xl"
      >
        <div className="flex items-start justify-between gap-4 border-b border-ink-600/60 p-5">
          <div className="min-w-0">
            <div className="mb-2 flex items-center gap-2">
              <SeverityBadge severity={selected.item.severity} />
            </div>
            <h2 className="break-all font-mono text-base font-semibold text-white">{id}</h2>
            {title && <p className="mt-1 text-sm text-slate-400">{title}</p>}
          </div>
          <button
            type="button"
            onClick={onClose}
            className="rounded p-1.5 text-slate-400 hover:bg-ink-700 hover:text-white"
            aria-label="Close"
          >
            <X className="h-5 w-5" />
          </button>
        </div>
        <div className="flex-1 space-y-5 overflow-y-auto p-5">
          <Body sel={selected} />
        </div>
      </aside>
    </div>
  )
}