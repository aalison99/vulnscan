import type {
  CreateScanRequest,
  Health,
  ScanCreated,
  ScanDetail,
  ScanSummary,
  ScannerName,
  Severity,
} from './types'

const BASE = '/api'

export class ApiError extends Error {
  status: number
  constructor(message: string, status: number) {
    super(message)
    this.status = status
  }
}

async function errorMessage(res: Response): Promise<string> {
  try {
    const body = await res.json()
    const d = body?.detail
    if (typeof d === 'string') return d
    if (Array.isArray(d)) {
      return d.map((e) => e?.msg ?? JSON.stringify(e)).join('; ')
    }
  } catch {
    /* not JSON */
  }
  return `Request failed (${res.status})`
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  let res: Response
  try {
    res = await fetch(BASE + path, init)
  } catch {
    throw new ApiError('Cannot reach the VulnScan backend', 0)
  }
  if (!res.ok) throw new ApiError(await errorMessage(res), res.status)
  if (res.status === 204) return undefined as T
  return (await res.json()) as T
}

export const api = {
  listScans: () => request<ScanSummary[]>('/scans'),

  getScan: (id: string) => request<ScanDetail>(`/scans/${encodeURIComponent(id)}`),

  createScan: (body: CreateScanRequest) =>
    request<ScanCreated>('/scans', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    }),

  uploadScan: (file: File, scanners: ScannerName[], severities: Severity[]) => {
    const form = new FormData()
    form.append('file', file)
    form.append('scanners', scanners.join(','))
    form.append('severities', severities.join(','))
    return request<ScanCreated>('/scans/upload', { method: 'POST', body: form })
  },

  deleteScan: (id: string) =>
    request<void>(`/scans/${encodeURIComponent(id)}`, { method: 'DELETE' }),

  health: () => request<Health>('/health'),

  /** Plain URL for <a href download>; the backend sets Content-Disposition. */
  exportUrl: (id: string, format: 'json' | 'csv') =>
    `${BASE}/scans/${encodeURIComponent(id)}/export?format=${format}`,
}