import axios from 'axios'
import { api } from './client'
import type {
  Project,
  ProjectSummary,
  FindingSummary,
  GlobalFindingSummary,
  Finding,
  ScanRun,
  ScannerInfo,
  SecurityReport,
  RemediationRecord,
  AiAnalysis,
  DashboardStats,
  ProjectConfig,
  CvssResult,
  HealthStatus,
} from '../types'

// ─── Health ───────────────────────────────────────────────────────────────────

export const healthApi = {
  check: () => axios.get<HealthStatus>('/health').then((r) => r.data),
}

// ─── Projects ─────────────────────────────────────────────────────────────────

export const projectsApi = {
  list: () => api.get<ProjectSummary[]>('/projects/').then((r) => r.data),
  get: (id: string) => api.get<Project>(`/projects/${id}`).then((r) => r.data),
  create: (data: { name: string; description?: string; target_path?: string; target_url?: string }) =>
    api.post<Project>('/projects/', data).then((r) => r.data),
  update: (
    id: string,
    data: Partial<Pick<Project, 'name' | 'description' | 'target_path' | 'target_url' | 'status'>>
  ) => api.patch<Project>(`/projects/${id}`, data).then((r) => r.data),
  delete: (id: string) => api.delete(`/projects/${id}`),
}

// ─── Scans ────────────────────────────────────────────────────────────────────

export const scansApi = {
  list: (projectId: string) =>
    api.get<ScanRun[]>(`/projects/${projectId}/scans/`).then((r) => r.data),
  trigger: (projectId: string, scannerIds?: string[] | null) =>
    api
      .post<ScanRun>(`/projects/${projectId}/scans/`, {
        scanner_ids: scannerIds ?? null,
      })
      .then((r) => r.data),
  get: (projectId: string, scanId: string) =>
    api.get<ScanRun>(`/projects/${projectId}/scans/${scanId}`).then((r) => r.data),
}

// ─── Findings ─────────────────────────────────────────────────────────────────

export const findingsApi = {
  list: (
    projectId: string,
    filters?: {
      severity?: string
      status?: string
      category?: string
      confidence?: string
      scan_id?: string
    }
  ) =>
    api
      .get<FindingSummary[]>(`/projects/${projectId}/findings/`, { params: filters })
      .then((r) => r.data),
  get: (projectId: string, findingId: string) =>
    api.get<Finding>(`/projects/${projectId}/findings/${findingId}`).then((r) => r.data),
  updateStatus: (projectId: string, findingId: string, status: string, note?: string) =>
    api
      .patch<Finding>(`/projects/${projectId}/findings/${findingId}/status`, { status, note })
      .then((r) => r.data),
  validate: (projectId: string, findingId: string, confidence: string, note?: string) =>
    api
      .post<Finding>(`/projects/${projectId}/findings/${findingId}/validate`, { confidence, note })
      .then((r) => r.data),
  listRemediation: (projectId: string, findingId: string) =>
    api
      .get<RemediationRecord[]>(`/projects/${projectId}/findings/${findingId}/remediation`)
      .then((r) => r.data),
  createRemediation: (
    projectId: string,
    findingId: string,
    data: { description: string; applied_by?: string; patch_diff?: string }
  ) =>
    api
      .post<RemediationRecord>(`/projects/${projectId}/findings/${findingId}/remediation`, data)
      .then((r) => r.data),
  retest: (projectId: string, findingId: string, remediationId: string, notes?: string) =>
    api
      .post<{ retest_status: string; notes: string; remediation_id: string }>(
        `/projects/${projectId}/findings/${findingId}/remediation/${remediationId}/retest`,
        { notes }
      )
      .then((r) => r.data),
}

// ─── Reports ──────────────────────────────────────────────────────────────────

export const reportsApi = {
  list: (projectId: string) =>
    api.get<SecurityReport[]>(`/projects/${projectId}/reports`).then((r) => r.data),
  generate: (projectId: string, data?: { scan_run_id?: string; title?: string }) =>
    api.post<SecurityReport>(`/projects/${projectId}/reports`, data ?? {}).then((r) => r.data),
  downloadUrl: (projectId: string, reportId: string) =>
    `/api/v1/projects/${projectId}/reports/${reportId}/download`,
}

// ─── Findings: CVSS + AI analysis ─────────────────────────────────────────────

export const findingAnalysisApi = {
  setCvss: (projectId: string, findingId: string, vector: string) =>
    api.post<CvssResult>(`/projects/${projectId}/findings/${findingId}/cvss`, { vector })
      .then((r) => r.data),
  runAiAnalysis: (projectId: string, findingId: string) =>
    api.post<AiAnalysis>(`/projects/${projectId}/findings/${findingId}/analyze`)
      .then((r) => r.data),
  getAiAnalysis: (projectId: string, findingId: string) =>
    api.get<AiAnalysis>(`/projects/${projectId}/findings/${findingId}/analyze`)
      .then((r) => r.data),
}

// ─── Global findings ──────────────────────────────────────────────────────────

export const globalFindingsApi = {
  list: (filters?: {
    severity?: string
    status?: string
    category?: string
    confidence?: string
    project_id?: string
    search?: string
  }) => api.get<GlobalFindingSummary[]>('/findings/', { params: filters }).then((r) => r.data),
}

// ─── Global scans ─────────────────────────────────────────────────────────────

export const globalScansApi = {
  list: (filters?: { status?: string; project_id?: string }) =>
    api.get<ScanRun[]>('/scans/', { params: filters }).then((r) => r.data),
}

// ─── Dashboard ────────────────────────────────────────────────────────────────

export const dashboardApi = {
  stats: () => api.get<DashboardStats>('/dashboard/stats').then((r) => r.data),
}

// ─── Scanner config ───────────────────────────────────────────────────────────

export const scannerConfigApi = {
  get: (projectId: string) =>
    api.get<ProjectConfig>(`/projects/${projectId}/scanner-config`).then((r) => r.data),
  update: (projectId: string, data: { enabled_scanners?: string[] | null; authorized_targets?: string[] }) =>
    api.patch<ProjectConfig>(`/projects/${projectId}/scanner-config`, data).then((r) => r.data),
}

// ─── Scanners ─────────────────────────────────────────────────────────────────

export const scannersApi = {
  list: () => api.get<ScannerInfo[]>('/scanners/').then((r) => r.data),
}
