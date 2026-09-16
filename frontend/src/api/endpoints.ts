import axios from 'axios'
import { api } from './client'
import type { Project, ProjectSummary, FindingSummary, Finding, ScanRun, HealthStatus } from '../types'

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
  trigger: (projectId: string, scannerIds?: string[]) =>
    api.post<ScanRun>(`/projects/${projectId}/scans/`, {
      scanner_ids: scannerIds ?? null,
    }).then((r) => r.data),
  get: (projectId: string, scanId: string) =>
    api.get<ScanRun>(`/projects/${projectId}/scans/${scanId}`).then((r) => r.data),
}

// ─── Findings ─────────────────────────────────────────────────────────────────

export const findingsApi = {
  list: (projectId: string, filters?: { severity?: string; status?: string; category?: string }) =>
    api
      .get<FindingSummary[]>(`/projects/${projectId}/findings/`, { params: filters })
      .then((r) => r.data),
  get: (projectId: string, findingId: string) =>
    api.get<Finding>(`/projects/${projectId}/findings/${findingId}`).then((r) => r.data),
  updateStatus: (projectId: string, findingId: string, status: string, note?: string) =>
    api
      .patch<Finding>(`/projects/${projectId}/findings/${findingId}/status`, { status, note })
      .then((r) => r.data),
}
