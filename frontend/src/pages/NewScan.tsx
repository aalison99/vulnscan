import { useRef, useState } from 'react'
import type { ChangeEvent, DragEvent, FormEvent } from 'react'
import { useNavigate } from 'react-router-dom'
import { Cloud, FileArchive, GitBranch, Container, Loader2, UploadCloud, X } from 'lucide-react'
import { api } from '../api'
import type { ScannerName, Severity } from '../types'
import { ALL_SCANNERS, SELECTABLE_SEVERITIES } from '../types'
import ScannerOptions from '../components/ScannerOptions'

type Tab = 'image' | 'repo' | 'archive' | 'aws'

const PRESETS = ['alpine:3.19', 'python:3.11-slim', 'nginx:latest']
const MAX_UPLOAD_MB = 200

const TABS: { key: Tab; label: string; icon: typeof Container }[] = [
  { key: 'image', label: 'Container Image', icon: Container },
  { key: 'repo', label: 'Git Repository', icon: GitBranch },
  { key: 'archive', label: 'Archive Upload', icon: UploadCloud },
  { key: 'aws', label: 'AWS Account', icon: Cloud },
]

const validArchive = (name: string) => /\.(zip|tar\.gz|tgz)$/i.test(name)

function formatSize(bytes: number): string {
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`
  return `${(bytes / 1024 / 1024).toFixed(1)} MB`
}

export default function NewScan() {
  const navigate = useNavigate()
  const inputRef = useRef<HTMLInputElement>(null)

  const [tab, setTab] = useState<Tab>('image')
  const [image, setImage] = useState('')
  const [repo, setRepo] = useState('')
  const [awsProfile, setAwsProfile] = useState('sample')
  const [awsRegions, setAwsRegions] = useState('')
  const [file, setFile] = useState<File | null>(null)
  const [dragging, setDragging] = useState(false)
  const [scanners, setScanners] = useState<ScannerName[]>([...ALL_SCANNERS])
  const [severities, setSeverities] = useState<Severity[]>([...SELECTABLE_SEVERITIES])
  const [submitting, setSubmitting] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const pickFile = (f: File | undefined) => {
    if (!f) return
    if (!validArchive(f.name)) {
      setError('Only .zip, .tar.gz and .tgz archives are supported')
      return
    }
    if (f.size > MAX_UPLOAD_MB * 1024 * 1024) {
      setError(`Archive exceeds the ${MAX_UPLOAD_MB} MB upload limit`)
      return
    }
    setError(null)
    setFile(f)
  }

  const onDrop = (e: DragEvent<HTMLDivElement>) => {
    e.preventDefault()
    setDragging(false)
    pickFile(e.dataTransfer.files?.[0])
  }

  const onInput = (e: ChangeEvent<HTMLInputElement>) => {
    pickFile(e.target.files?.[0])
    e.target.value = '' // allow re-selecting the same file
  }

  const submit = async (e: FormEvent) => {
    e.preventDefault()
    setError(null)

    if (tab !== 'aws') {
      if (scanners.length === 0) return setError('Select at least one scanner')
      if (severities.length === 0) return setError('Select at least one severity')
    }

    setSubmitting(true)
    try {
      let res
      if (tab === 'aws') {
        const profile = awsProfile.trim()
        if (!profile) throw new Error('Enter an AWS profile name, "env", or "sample"')
        const regions = awsRegions.split(',').map((r) => r.trim()).filter(Boolean).join(',')
        res = await api.createScan({
          scan_type: 'aws',
          target: regions && profile !== 'sample' ? `${profile}@${regions}` : profile,
          scanners: [...ALL_SCANNERS],
          severities: [...SELECTABLE_SEVERITIES],
        })
      } else if (tab === 'archive') {
        if (!file) throw new Error('Choose an archive to upload')
        res = await api.uploadScan(file, scanners, severities)
      } else {
        const target = (tab === 'image' ? image : repo).trim()
        if (!target) {
          throw new Error(tab === 'image' ? 'Enter an image reference' : 'Enter a repository URL')
        }
        res = await api.createScan({
          scan_type: tab === 'image' ? 'image' : 'repo',
          target,
          scanners,
          severities,
        })
      }
      navigate(`/scans/${res.scan_id}`)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to start scan')
      setSubmitting(false)
    }
  }

  return (
    <div className="mx-auto max-w-3xl space-y-6">
      <div>
        <h1 className="text-2xl font-semibold text-white">New Scan</h1>
        <p className="mt-1 text-sm text-slate-400">
          Scan a container image, a Git repository or a code archive.
        </p>
      </div>

      <form onSubmit={submit} className="card space-y-6 p-6">
        <div className="flex gap-1 rounded-lg bg-ink-900 p-1">
          {TABS.map(({ key, label, icon: Icon }) => (
            <button
              key={key}
              type="button"
              onClick={() => {
                setTab(key)
                setError(null)
              }}
              className={`flex flex-1 items-center justify-center gap-2 rounded-md px-3 py-2 text-sm font-medium transition-colors ${
                tab === key
                  ? 'bg-ink-700 text-white'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              <Icon className="h-4 w-4" />
              <span className="hidden sm:inline">{label}</span>
            </button>
          ))}
        </div>

        {tab === 'image' && (
          <div className="space-y-3">
            <label className="block text-sm font-medium text-slate-300" htmlFor="image">
              Image reference
            </label>
            <input
              id="image"
              className="input font-mono"
              placeholder="e.g. nginx:latest or ghcr.io/org/app:1.2.3"
              value={image}
              onChange={(e) => setImage(e.target.value)}
              autoComplete="off"
              spellCheck={false}
            />
            <div className="flex flex-wrap items-center gap-2">
              <span className="text-xs text-slate-500">Quick test:</span>
              {PRESETS.map((p) => (
                <button
                  key={p}
                  type="button"
                  onClick={() => setImage(p)}
                  className="rounded-full border border-ink-600 bg-ink-700/40 px-3 py-1 font-mono text-xs text-slate-300 hover:border-emerald-500/50 hover:text-emerald-300"
                >
                  {p}
                </button>
              ))}
            </div>
          </div>
        )}

        {tab === 'repo' && (
          <div className="space-y-3">
            <label className="block text-sm font-medium text-slate-300" htmlFor="repo">
              Repository URL
            </label>
            <input
              id="repo"
              className="input font-mono"
              placeholder="https://github.com/owner/repo"
              value={repo}
              onChange={(e) => setRepo(e.target.value)}
              autoComplete="off"
              spellCheck={false}
            />
            <p className="text-xs text-slate-500">
              Public http(s) repositories only. Credentials in the URL are not supported.
            </p>
          </div>
        )}

        {tab === 'aws' && (
          <div className="space-y-3">
            <label className="block text-sm font-medium text-slate-300" htmlFor="awsprofile">
              AWS profile
            </label>
            <input
              id="awsprofile"
              className="input font-mono"
              placeholder="profile name, env, or sample"
              value={awsProfile}
              onChange={(e) => setAwsProfile(e.target.value)}
              autoComplete="off"
              spellCheck={false}
            />
            <div className="flex flex-wrap items-center gap-2 text-xs text-slate-500">
              <span>Presets:</span>
              {['sample', 'env'].map((p) => (
                <button
                  key={p}
                  type="button"
                  onClick={() => setAwsProfile(p)}
                  className="rounded-full border border-ink-600 bg-ink-700/40 px-3 py-1 font-mono text-slate-300 hover:border-emerald-500/50 hover:text-emerald-300"
                >
                  {p}
                </button>
              ))}
            </div>
            <label className="block text-sm font-medium text-slate-300" htmlFor="awsregions">
              Regions (optional, comma separated; empty scans all enabled regions)
            </label>
            <input
              id="awsregions"
              className="input font-mono"
              placeholder="ap-south-1,us-east-1"
              value={awsRegions}
              onChange={(e) => setAwsRegions(e.target.value)}
              autoComplete="off"
              spellCheck={false}
            />
            <p className="text-xs text-slate-500">
              <code>sample</code> scans built-in demo data with no AWS access. <code>env</code> uses the
              server's environment credentials; any other value is a named profile on the server. The scan is
              read-only and credentials are never stored.
            </p>
          </div>
        )}

        {tab === 'archive' && (
          <div>
            <div
              onDragOver={(e) => {
                e.preventDefault()
                setDragging(true)
              }}
              onDragLeave={() => setDragging(false)}
              onDrop={onDrop}
              onClick={() => inputRef.current?.click()}
              className={`flex cursor-pointer flex-col items-center justify-center gap-3 rounded-xl border-2 border-dashed px-6 py-12 text-center transition-colors ${
                dragging
                  ? 'border-emerald-400 bg-emerald-500/5'
                  : 'border-ink-600 hover:border-slate-500'
              }`}
            >
              <UploadCloud className="h-9 w-9 text-slate-500" />
              <div className="text-sm text-slate-300">
                Drag &amp; drop an archive here, or{' '}
                <span className="text-emerald-400">browse</span>
              </div>
              <div className="text-xs text-slate-500">
                .zip, .tar.gz or .tgz — up to {MAX_UPLOAD_MB} MB
              </div>
              <input
                ref={inputRef}
                type="file"
                accept=".zip,.tar.gz,.tgz"
                className="hidden"
                onChange={onInput}
              />
            </div>

            {file && (
              <div className="mt-3 flex items-center justify-between rounded-lg border border-ink-600 bg-ink-900 px-3 py-2">
                <div className="flex min-w-0 items-center gap-2 text-sm text-slate-200">
                  <FileArchive className="h-4 w-4 shrink-0 text-emerald-400" />
                  <span className="truncate font-mono">{file.name}</span>
                  <span className="shrink-0 text-xs text-slate-500">{formatSize(file.size)}</span>
                </div>
                <button
                  type="button"
                  onClick={() => setFile(null)}
                  className="rounded p-1 text-slate-500 hover:text-white"
                  aria-label="Remove file"
                >
                  <X className="h-4 w-4" />
                </button>
              </div>
            )}
          </div>
        )}

        {tab !== 'aws' && (
          <div className="border-t border-ink-600/60 pt-6">
            <ScannerOptions
              scanners={scanners}
              severities={severities}
              onScanners={setScanners}
              onSeverities={setSeverities}
            />
          </div>
        )}

        {error && (
          <div className="rounded-lg border border-red-500/30 bg-red-500/10 px-4 py-3 text-sm text-red-300">
            {error}
          </div>
        )}

        <div className="flex justify-end">
          <button type="submit" className="btn-primary" disabled={submitting}>
            {submitting && <Loader2 className="h-4 w-4 animate-spin" />}
            {submitting ? 'Starting…' : 'Start Scan'}
          </button>
        </div>
      </form>
    </div>
  )
}