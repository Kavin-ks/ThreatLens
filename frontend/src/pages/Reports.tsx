import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import {
  FileText,
  FileDown,
  Plus,
  Loader2,
  ShieldCheck,
  Calendar,
  AlertCircle,
  FolderOpen,
  CheckCircle2,
  ExternalLink,
  Sparkles,
} from 'lucide-react'
import { TopBar } from '../components/layout/TopBar'
import { EmptyState } from '../components/common/EmptyState'
import { projectsApi, reportsApi } from '../api/endpoints'
import { SAMPLE_PROJECTS } from '../lib/sampleProjects'
import { formatDate } from '../lib/utils'
import type { SecurityReport } from '../types'

export default function Reports() {
  const queryClient = useQueryClient()
  const [selectedProjectId, setSelectedProjectId] = useState<string>('')
  const [reportTitle, setReportTitle] = useState<string>('')
  const [genError, setGenError] = useState<string | null>(null)
  const [successMsg, setSuccessMsg] = useState<string | null>(null)

  // 1. Fetch available projects
  const { data: serverProjects = [] } = useQuery({
    queryKey: ['projects'],
    queryFn: projectsApi.list,
  })
  const projects = serverProjects.length > 0 ? serverProjects : SAMPLE_PROJECTS

  // Set default selected project
  const currentProjectId = selectedProjectId || (projects[0]?.id ?? '')

  // 2. Fetch reports for the selected project (or all projects)
  const { data: reports = [], isLoading: reportsLoading } = useQuery({
    queryKey: ['reports', currentProjectId],
    queryFn: () => (currentProjectId ? reportsApi.list(currentProjectId) : Promise.resolve([])),
    enabled: !!currentProjectId,
  })

  // 3. Generate Report Mutation
  const generateMutation = useMutation({
    mutationFn: (data: { projectId: string; title?: string }) =>
      reportsApi.generate(data.projectId, { title: data.title || undefined }),
    onSuccess: (newReport) => {
      setGenError(null)
      setReportTitle('')
      setSuccessMsg(`Report "${newReport.title}" generated successfully!`)
      queryClient.invalidateQueries({ queryKey: ['reports', currentProjectId] })
      setTimeout(() => setSuccessMsg(null), 4000)
    },
    onError: (err: Error) => {
      setGenError(err.message || 'Failed to generate report. Please try again.')
    },
  })

  const handleGenerate = (e: React.FormEvent) => {
    e.preventDefault()
    if (!currentProjectId) return
    setGenError(null)
    setSuccessMsg(null)
    generateMutation.mutate({
      projectId: currentProjectId,
      title: reportTitle.trim() || undefined,
    })
  }

  // Pre-configured demonstration reports when database has none yet
  const sampleReports: Array<{
    id: string
    title: string
    projectName: string
    projectId: string
    findingCount: number
    date: string
    compliance: string
  }> = [
    {
      id: 'demo-report-threatlens',
      title: 'World Monitor Security Assessment - Executive & Technical Audit Report',
      projectName: 'ThreatLens Security Assessment',
      projectId: '11111111-2222-3333-4444-555555555555',
      findingCount: 18,
      date: new Date(Date.now() - 3600000).toISOString(),
      compliance: 'NIST SP 800-218 · ISO/IEC 30111 · CERT-In',
    },
    {
      id: 'demo-report-ledgerlens',
      title: 'LedgerLens Smart Contract Security & AML Compliance Audit',
      projectName: 'LedgerLens - Blockchain Forensic & AML Analysis',
      projectId: '22222222-3333-4444-5555-666666666666',
      findingCount: 12,
      date: new Date(Date.now() - 86400000).toISOString(),
      compliance: 'Smart Contract Audit · OWASP Top 10 · CVSS v3.1',
    },
  ]

  return (
    <div className="flex flex-col h-full">
      <TopBar
        title="Security & Compliance Reports"
        subtitle="Generate, preview, and export audit-ready PDF documentation"
      />

      <div className="flex-1 overflow-y-auto p-6 space-y-6">
        {/* Compliance Badges Banner */}
        <div className="bg-tl-surface border border-tl-border rounded-lg p-4 flex flex-wrap items-center justify-between gap-4">
          <div className="flex items-center gap-3">
            <div className="w-9 h-9 rounded-lg bg-tl-blue/10 border border-tl-blue/30 flex items-center justify-center flex-shrink-0">
              <ShieldCheck size={20} className="text-tl-blue" />
            </div>
            <div>
              <div className="text-xs font-semibold text-tl-text">
                Audit-Ready Standardized Documentation
              </div>
              <div className="text-[11px] text-tl-muted">
                Meets sovereign requirements for NTRO, CERT-In, and federal DevSecOps frameworks.
              </div>
            </div>
          </div>

          <div className="flex items-center gap-2 flex-wrap text-[11px] font-mono">
            <span className="px-2 py-0.5 rounded bg-tl-surface2 border border-tl-border text-tl-muted">
              NIST SP 800-218 (SSDF)
            </span>
            <span className="px-2 py-0.5 rounded bg-tl-surface2 border border-tl-border text-tl-muted">
              ISO/IEC 30111
            </span>
            <span className="px-2 py-0.5 rounded bg-tl-surface2 border border-tl-border text-tl-muted">
              FIRST CVSS v3.1
            </span>
            <span className="px-2 py-0.5 rounded bg-tl-surface2 border border-tl-border text-tl-muted">
              OWASP Top 10:2021
            </span>
          </div>
        </div>

        {/* Generate Report Card */}
        <div className="bg-tl-surface border border-tl-border rounded-lg p-5">
          <div className="flex items-center justify-between mb-4">
            <div className="flex items-center gap-2">
              <Sparkles size={16} className="text-tl-blue" />
              <h2 className="text-sm font-semibold text-tl-text">Generate New Assessment Report</h2>
            </div>
            <span className="text-xs text-tl-muted">Vector PDF (A4)</span>
          </div>

          <form onSubmit={handleGenerate} className="grid grid-cols-1 md:grid-cols-12 gap-3 items-end">
            <div className="md:col-span-4">
              <label className="block text-xs font-medium text-tl-text2 mb-1">
                Select Assessment Project
              </label>
              <select
                value={currentProjectId}
                onChange={(e) => setSelectedProjectId(e.target.value)}
                className="w-full bg-tl-surface2 border border-tl-border rounded-md px-3 py-2 text-xs text-tl-text focus:outline-none focus:border-tl-blue transition-colors"
              >
                {projects.map((p) => (
                  <option key={p.id} value={p.id}>
                    {p.name}
                  </option>
                ))}
              </select>
            </div>

            <div className="md:col-span-5">
              <label className="block text-xs font-medium text-tl-text2 mb-1">
                Custom Report Title <span className="text-tl-muted">(optional)</span>
              </label>
              <input
                type="text"
                placeholder="e.g. Q3 Application Security Vulnerability Audit"
                value={reportTitle}
                onChange={(e) => setReportTitle(e.target.value)}
                className="w-full bg-tl-surface2 border border-tl-border rounded-md px-3 py-2 text-xs text-tl-text placeholder:text-tl-muted focus:outline-none focus:border-tl-blue transition-colors"
              />
            </div>

            <div className="md:col-span-3">
              <button
                type="submit"
                disabled={generateMutation.isPending || !currentProjectId}
                className="w-full flex items-center justify-center gap-2 px-4 py-2 rounded-md bg-tl-blue text-white text-xs font-medium hover:bg-tl-blue2 disabled:opacity-60 transition-colors"
              >
                {generateMutation.isPending ? (
                  <>
                    <Loader2 size={13} className="animate-spin" />
                    <span>Compiling PDF…</span>
                  </>
                ) : (
                  <>
                    <FileText size={13} />
                    <span>Generate Audit PDF</span>
                  </>
                )}
              </button>
            </div>
          </form>

          {genError && (
            <div className="mt-3 flex items-center gap-2 px-3 py-2 rounded bg-red-500/10 border border-red-500/30 text-xs text-red-400">
              <AlertCircle size={14} className="flex-shrink-0" />
              <span>{genError}</span>
            </div>
          )}

          {successMsg && (
            <div className="mt-3 flex items-center gap-2 px-3 py-2 rounded bg-emerald-500/10 border border-emerald-500/30 text-xs text-emerald-400">
              <CheckCircle2 size={14} className="flex-shrink-0" />
              <span>{successMsg}</span>
            </div>
          )}
        </div>

        {/* Existing Reports Section */}
        <div>
          <div className="flex items-center justify-between mb-3">
            <h2 className="text-sm font-semibold text-tl-text">Generated Security Reports</h2>
            <span className="text-xs text-tl-muted font-mono">
              {reports.length} report{reports.length !== 1 ? 's' : ''} on record
            </span>
          </div>

          <div className="bg-tl-surface border border-tl-border rounded-lg overflow-hidden">
            {reportsLoading ? (
              <div className="flex items-center justify-center py-12 text-tl-muted text-xs gap-2">
                <Loader2 size={16} className="animate-spin" />
                Loading reports…
              </div>
            ) : reports.length > 0 ? (
              <div className="divide-y divide-tl-border">
                {reports.map((report) => {
                  const meta = report.metadata_json
                    ? (() => {
                        try {
                          return JSON.parse(report.metadata_json)
                        } catch {
                          return null
                        }
                      })()
                    : null

                  return (
                    <div
                      key={report.id}
                      className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 p-4 hover:bg-tl-surface2 transition-colors"
                    >
                      <div className="flex items-start gap-3 min-w-0">
                        <div className="w-8 h-8 rounded-lg bg-tl-blue/10 border border-tl-blue/20 flex items-center justify-center flex-shrink-0 mt-0.5">
                          <FileText size={16} className="text-tl-blue" />
                        </div>
                        <div className="min-w-0">
                          <div className="text-xs font-semibold text-tl-text truncate">
                            {report.title}
                          </div>
                          <div className="flex items-center gap-2 text-[11px] text-tl-muted mt-1 flex-wrap">
                            <span className="flex items-center gap-1">
                              <Calendar size={11} />
                              {formatDate(report.created_at)}
                            </span>
                            <span>·</span>
                            <span>{meta?.finding_count ?? 'Full'} findings analyzed</span>
                            <span>·</span>
                            <span className="uppercase font-mono text-[10px] px-1.5 py-0.2 rounded bg-tl-surface border border-tl-border">
                              {report.format}
                            </span>
                            <span>·</span>
                            <span className="text-emerald-400 font-medium">Audit Ready</span>
                          </div>
                        </div>
                      </div>

                      <div className="flex items-center gap-2 flex-shrink-0 w-full sm:w-auto justify-end">
                        <a
                          href={reportsApi.downloadUrl(report.project_id, report.id)}
                          target="_blank"
                          rel="noreferrer"
                          className="flex items-center gap-1.5 px-3 py-1.5 rounded bg-tl-surface border border-tl-border text-xs font-medium text-tl-text hover:border-tl-blue hover:bg-tl-surface2 transition-colors"
                        >
                          <ExternalLink size={12} />
                          Preview
                        </a>
                        <a
                          href={reportsApi.downloadUrl(report.project_id, report.id)}
                          download={`${report.title.replace(/\s+/g, '_')}.pdf`}
                          className="flex items-center gap-1.5 px-3 py-1.5 rounded bg-tl-blue text-white text-xs font-medium hover:bg-tl-blue2 transition-colors shadow-sm"
                        >
                          <FileDown size={12} />
                          Download PDF
                        </a>
                      </div>
                    </div>
                  )
                })}
              </div>
            ) : (
              /* Fallback demonstration list when none are generated yet */
              <div className="divide-y divide-tl-border">
                {sampleReports.map((demo) => (
                  <div
                    key={demo.id}
                    className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 p-4 hover:bg-tl-surface2 transition-colors"
                  >
                    <div className="flex items-start gap-3 min-w-0">
                      <div className="w-8 h-8 rounded-lg bg-tl-blue/10 border border-tl-blue/20 flex items-center justify-center flex-shrink-0 mt-0.5">
                        <FileText size={16} className="text-tl-blue" />
                      </div>
                      <div className="min-w-0">
                        <div className="text-xs font-semibold text-tl-text truncate">
                          {demo.title}
                        </div>
                        <div className="flex items-center gap-2 text-[11px] text-tl-muted mt-1 flex-wrap">
                          <span className="px-1.5 py-0.5 rounded bg-tl-surface border border-tl-border text-tl-text2 text-[10px]">
                            {demo.projectName}
                          </span>
                          <span>·</span>
                          <span>{demo.findingCount} findings verified</span>
                          <span>·</span>
                          <span className="text-tl-muted">{demo.compliance}</span>
                        </div>
                      </div>
                    </div>

                    <button
                      onClick={() => {
                        setSelectedProjectId(demo.projectId)
                        generateMutation.mutate({
                          projectId: demo.projectId,
                          title: demo.title,
                        })
                      }}
                      disabled={generateMutation.isPending}
                      className="flex items-center gap-1.5 px-3 py-1.5 rounded bg-tl-blue text-white text-xs font-medium hover:bg-tl-blue2 transition-colors flex-shrink-0"
                    >
                      {generateMutation.isPending && currentProjectId === demo.projectId ? (
                        <Loader2 size={12} className="animate-spin" />
                      ) : (
                        <FileDown size={12} />
                      )}
                      Generate & Download
                    </button>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  )
}
