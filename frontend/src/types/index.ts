// ─── Enums ────────────────────────────────────────────────────────────────────

export type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO'
export type Confidence = 'CONFIRMED' | 'LIKELY' | 'POSSIBLE' | 'FALSE_POSITIVE'
export type FindingStatus =
  | 'DETECTED'
  | 'VALIDATING'
  | 'CONFIRMED'
  | 'REJECTED'
  | 'REMEDIATION'
  | 'RETESTING'
  | 'RESOLVED'

export type SecurityCategory =
  | 'authentication'
  | 'authorization'
  | 'injection'
  | 'xss'
  | 'api_security'
  | 'dependencies'
  | 'secrets'
  | 'configuration'
  | 'session'
  | 'cryptography'
  | 'headers'
  | 'data_exposure'
  | 'ssrf'
  | 'secure_communication'
  | 'rate_limiting'
  | 'privacy'
  | 'other'

export type ProjectStatus = 'active' | 'archived'
export type ScanStatus = 'pending' | 'running' | 'completed' | 'failed' | 'cancelled'

// ─── API shapes ───────────────────────────────────────────────────────────────

export interface Project {
  id: string
  name: string
  description: string | null
  target_path: string | null
  target_url: string | null
  status: ProjectStatus
  stack_info: string | null
  created_at: string
  updated_at: string
}

export interface ProjectSummary {
  id: string
  name: string
  description: string | null
  status: ProjectStatus
  total_findings: number
  confirmed_findings: number
  critical_count: number
  high_count: number
  last_scan_at: string | null
  created_at: string
}

export interface ScanRun {
  id: string
  project_id: string
  status: ScanStatus
  scanner_config: string | null
  summary: string | null
  error_message: string | null
  celery_task_id: string | null
  created_at: string
  updated_at: string
}

export interface Evidence {
  id: string
  evidence_type: string
  content: string | null
  file_path: string | null
  metadata_json: string | null
  title: string | null
  description: string | null
  created_at: string
}

export interface Finding {
  id: string
  project_id: string
  scan_run_id: string
  scanner_id: string
  title: string
  description: string
  category: SecurityCategory
  severity: Severity
  confidence: Confidence
  status: FindingStatus
  affected_component: string | null
  affected_file: string | null
  affected_line: number | null
  affected_endpoint: string | null
  cwe_id: string | null
  owasp_category: string | null
  cvss_score: number | null
  impact: string | null
  remediation: string | null
  evidence: Evidence[]
  created_at: string
  updated_at: string
}

export interface FindingSummary {
  id: string
  title: string
  category: SecurityCategory
  severity: Severity
  confidence: Confidence
  status: FindingStatus
  affected_file: string | null
  scanner_id: string
  created_at: string
}

// ─── API response wrappers ────────────────────────────────────────────────────

export interface HealthStatus {
  status: 'healthy' | 'degraded'
  version: string
  timestamp: string
  components: {
    database: { status: 'ok' | 'error'; error?: string }
  }
}
