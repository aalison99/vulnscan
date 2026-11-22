export type ScanStatus = 'queued' | 'running' | 'completed' | 'failed'
export type ScanType = 'image' | 'repo' | 'fs'
export type ScannerName = 'vuln' | 'secret' | 'misconfig'
export type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'UNKNOWN'

export const ALL_SCANNERS: ScannerName[] = ['vuln', 'secret', 'misconfig']
export const SELECTABLE_SEVERITIES: Severity[] = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']

export interface SeverityCounts {
  critical: number
  high: number
  medium: number
  low: number
  unknown: number
}

export interface ScanSummary {
  id: string
  target: string
  scan_type: ScanType
  status: ScanStatus
  scanners: ScannerName[]
  severities: Severity[]
  error: string | null
  created_at: string
  started_at: string | null
  finished_at: string | null
  severity_counts: SeverityCounts // vulnerabilities only
  vulnerability_count: number
  misconfig_count: number
  secret_count: number
}

export interface Vulnerability {
  id: string
  pkg_name: string
  installed_version: string
  fixed_version: string | null
  severity: Severity
  title: string
  description: string
  cvss_score: number | null
  cvss_vector: string | null
  target: string
  pkg_type: string
  published_date: string | null
  primary_url: string | null
  references: string[]
  remediation: string
}

export interface Misconfiguration {
  id: string
  avd_id: string | null
  type: string
  title: string
  description: string
  message: string
  severity: Severity
  target: string
  start_line: number | null
  end_line: number | null
  provider: string | null
  service: string | null
  primary_url: string | null
  references: string[]
  remediation: string
}

export interface Secret {
  rule_id: string
  category: string
  title: string
  severity: Severity
  target: string
  start_line: number | null
  end_line: number | null
  match: string
  remediation: string
}

export interface ScanDetail extends ScanSummary {
  os: string | null
  misconfig_severity_counts: SeverityCounts
  secret_severity_counts: SeverityCounts
  vulnerabilities: Vulnerability[]
  misconfigurations: Misconfiguration[]
  secrets: Secret[]
}

export interface CreateScanRequest {
  scan_type: 'image' | 'repo'
  target: string
  scanners: ScannerName[]
  severities: Severity[]
}

export interface ScanCreated {
  scan_id: string
  status: ScanStatus
}

export interface Health {
  status: 'ok' | 'degraded'
  backend: string
  scanner: { ok: boolean; version: string | null; error?: string }
  scanner_server: {
    url: string
    reachable: boolean
    status_code?: number
    error?: string
  }
}