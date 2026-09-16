import { useState } from 'react'
import { Link, useNavigate, useParams } from 'react-router-dom'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import {
  ArrowLeft,
  FolderOpen,
  Globe,
  Play,
  AlertTriangle,
  ShieldAlert,
  Clock,
  CheckCircle2,
  Activity,
  ChevronRight,
  X,
  Loader2,
  AlertCircle,
  FileDown,
  FileText,
} from 'lucide-react'
import { TopBar } from '../components/layout/TopBar'
import { SeverityBadge } from '../components/common/SeverityBadge'
import { StatusBadge } from '../components/common/StatusBadge'
import { ConfidenceBadge } from '../components/common/ConfidenceBadge'
import { EmptyState } from '../components/common/EmptyState'
import { projectsApi, scansApi, findingsApi, reportsApi } from '../api/endpoints'
import { formatRelative, formatDate } from '../lib/utils'
import type { ScanStatus, Severity } from '../types'

const SEV_ORDER: Severity[] = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']

const SEV_COLORS: Record<Severity, string> = {
  CRITICAL: 'text-red-400',
  HIGH:     'text-orange-400',
  MEDIUM:   'text-yellow-400',
  LOW:      'text-emerald-400',
  INFO:     'text-tl-muted',
}

function ScanStatusChip({ status }: { status: ScanStatus }) {
  const cfg: Record<ScanStatus, { label: string; cls: string; dot: string }> = {
    pending:   { label: 'Pending',   cls: 'text-tl-muted',   dot: 'bg-tl-muted' },
    running:   { label: 'Running',   cls: 'text-tl-blue',    dot: 'bg-tl-blue animate-pulse' },
    completed: { label: 'Completed', cls: 'text-emerald-400', dot: 'bg-emerald-400' },
    failed:    { label: 'Failed',    cls: 'text-red-400',     dot: 'bg-red-400' },
    cancelled: { label: 'Cancelled', cls: 'text-tl-muted',    dot: 'bg-tl-muted' },
  }
  const { label, cls, dot } = cfg[status] ?? cfg.pending
  return (
    <span className={`inline-flex items-center gap-1.5 text-xs font-medium ${cls}`}>
      <span className={`w-1.5 h-1.5 rounded-full flex-shrink-0 ${dot}`} />
      {label}
    </span>
  )
}

type Tab = 'overview' | 'findings' | 'scans' | 'reports'

export default function ProjectDetail() {
  const { id } = useParams<{ id: string }>()
  const navigate = useNavigate()
  const queryClient = useQueryClient()
  const [activeTab, setActiveTab] = useState<Tab>('overview')
  const [scanning, setScanning] = useState(false)
  const [scanError, setScanError] = useState<string | null>(null)

  const { data: project, isLoading: projLoading, isError: projError } = useQuery({
    queryKey: ['project', id],
    queryFn: () => projectsApi.get(id!),
    enabled: !!id,
  })

  const { data: scans = [] } = useQuery({
    queryKey: ['scans', id],
    queryFn: () => scansApi.list(id!),
    enabled: !!id,
    refetchInterval: (query) => {
      const data = query.state.data ?? []
      const hasActive = data.some((s) => s.status === 'pending' || s.status === 'running')
      return hasActive ? 2000 : false
    },
  })

  const { data: findings = [] } = useQuery({
    queryKey: ['findings', id],
    queryFn: () => findingsApi.list(id!),
    enabled: !!id,
  })

  const triggerMutation = useMutation({
    mutationFn: () => scansApi.trigger(id!),
    onSuccess: (scanRun) => {
      setScanning(false)
      queryClient.invalidateQueries({ queryKey: ['scans', id] })
      queryClient.invalidateQueries({ queryKey: ['projects'] })
      navigate(`/projects/${id}/scans/${scanRun.id}`)
    },
    onError: (err: Error) => {
      setScanning(false)
      setScanError(err.message)
    },
  })

  const handleStartScan = () => {
    setScanError(null)
    setScanning(true)
    triggerMutation.mutate()
  }

  if (projLoading) {
    return (
      <div className="flex items-center justify-center h-full">
        <Loader2 size={20} className="animate-spin text-tl-muted" />
      </div>
    )
  }

  if (projError || !project) {
    return (
      <div className="flex flex-col items-center justify-center h-full gap-3">
        <AlertCircle size={24} className="text-red-400" />
        <p className="text-sm text-tl-muted">Project not found.</p>
        <Link to="/projects" className="text-xs text-tl-blue hover:underline">
          Back to projects
        </Link>
      </div>
    )
  }

  // Counts
  const countBySev = SEV_ORDER.reduce((acc, s) => {
    acc[s] = findings.filter((f) => f.severity === s).length
    return acc
  }, {} as Record<Severity, number>)

  const tabs: { key: Tab; label: string }[] = [
    { key: 'overview', label: 'Overview' },
    { key: 'findings', label: `Findings (${findings.length})` },
    { key: 'scans',    label: `Scans (${scans.length})` },
    { key: 'reports',  label: 'Reports' },
  ]

  return (
    <div className="flex flex-col h-full">
      <TopBar
        title={project.name}
        subtitle={project.description ?? undefined}
        actions={
          <div className="flex items-center gap-2">
            <button
              onClick={handleStartScan}
              disabled={scanning || triggerMutation.isPending}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-md bg-tl-blue text-white text-xs font-medium hover:bg-tl-blue2 disabled:opacity-60 disabled:cursor-not-allowed transition-colors"
            >
              {scanning || triggerMutation.isPending ? (
                <Loader2 size={12} className="animate-spin" />
              ) : (
                <Play size={12} />
              )}
              {scanning || triggerMutation.isPending ? 'Starting…' : 'Start Scan'}
            </button>
            <button
              onClick={() => navigate(-1)}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-md text-tl-muted hover:text-tl-text2 hover:bg-tl-surface2 text-xs transition-colors"
            >
              <ArrowLeft size={13} />
              Back
            </button>
          </div>
        }
      />

      {/* Tabs */}
      <div className="border-b border-tl-border px-6 flex gap-1">
        {tabs.map((t) => (
          <button
            key={t.key}
            onClick={() => setActiveTab(t.key)}
            className={`px-3 py-2.5 text-xs font-medium border-b-2 transition-colors ${
              activeTab === t.key
                ? 'border-tl-blue text-tl-blue'
                : 'border-transparent text-tl-muted hover:text-tl-text2'
            }`}
          >
            {t.label}
          </button>
        ))}
      </div>

      {scanError && (
        <div className="mx-6 mt-3 flex items-start gap-2 px-4 py-3 rounded-lg bg-red-500 bg-opacity-10 border border-red-500 border-opacity-30 text-sm text-red-400">
          <AlertCircle size={15} className="flex-shrink-0 mt-0.5" />
          <span>{scanError}</span>
          <button onClick={() => setScanError(null)} className="ml-auto flex-shrink-0">
            <X size={14} />
          </button>
        </div>
      )}

      <div className="flex-1 overflow-y-auto p-6 space-y-6">
        {/* ── OVERVIEW TAB ── */}
        {activeTab === 'overview' && (
          <>
            {/* Target info */}
            <div className="flex flex-wrap gap-3">
              {project.target_path && (
                <div className="flex items-center gap-1.5 text-xs text-tl-muted bg-tl-surface border border-tl-border rounded-md px-3 py-1.5">
                  <FolderOpen size={12} className="text-tl-blue opacity-70" />
                  <span className="font-mono truncate max-w-xs">{project.target_path}</span>
                </div>
              )}
              {project.target_url && (
                <div className="flex items-center gap-1.5 text-xs text-tl-muted bg-tl-surface border border-tl-border rounded-md px-3 py-1.5">
                  <Globe size={12} className="text-tl-blue opacity-70" />
                  <span className="font-mono truncate max-w-xs">{project.target_url}</span>
                </div>
              )}
            </div>

            {/* Severity stats */}
            <div className="grid grid-cols-2 sm:grid-cols-5 gap-3">
              {SEV_ORDER.map((sev) => (
                <div key={sev} className="bg-tl-surface border border-tl-border rounded-lg p-3 text-center">
                  <div className={`text-xl font-semibold font-mono ${SEV_COLORS[sev]}`}>
                    {countBySev[sev]}
                  </div>
                  <div className="text-[10px] font-mono text-tl-muted mt-0.5 uppercase tracking-wider">
                    {sev}
                  </div>
                </div>
              ))}
            </div>

            {/* Recent scans */}
            <div>
              <div className="flex items-center justify-between mb-3">
                <h2 className="text-sm font-semibold text-tl-text">Recent Scans</h2>
                <button
                  onClick={() => setActiveTab('scans')}
                  className="text-xs text-tl-blue hover:underline"
                >
                  View all
                </button>
              </div>
              <div className="bg-tl-surface border border-tl-border rounded-lg overflow-hidden">
                {scans.length === 0 ? (
                  <EmptyState
                    icon={Activity}
                    title="No scans yet"
                    description='Click "Start Scan" to run your first security scan.'
                  />
                ) : (
                  <div className="divide-y divide-tl-border">
                    {scans.slice(0, 5).map((scan) => {
                      const summary = scan.summary ? (() => { try { return JSON.parse(scan.summary) } catch { return null } })() : null
                      return (
                        <Link
                          key={scan.id}
                          to={`/projects/${id}/scans/${scan.id}`}
                          className="flex items-center gap-4 px-4 py-3 hover:bg-tl-surface2 transition-colors group"
                        >
                          <div className="flex-1 min-w-0">
                            <div className="flex items-center gap-2">
                              <ScanStatusChip status={scan.status} />
                              <span className="text-xs text-tl-muted">
                                {formatRelative(scan.created_at)}
                              </span>
                            </div>
                            {summary && (
                              <div className="text-xs text-tl-muted mt-0.5">
                                {summary.total_confirmed ?? 0} confirmed · {summary.scanner_count ?? 0} scanner{(summary.scanner_count ?? 0) !== 1 ? 's' : ''}
                              </div>
                            )}
                          </div>
                          <ChevronRight size={14} className="text-tl-muted opacity-0 group-hover:opacity-100 transition-opacity flex-shrink-0" />
                        </Link>
                      )
                    })}
                  </div>
                )}
              </div>
            </div>

            {/* Recent findings */}
            {findings.length > 0 && (
              <div>
                <div className="flex items-center justify-between mb-3">
                  <h2 className="text-sm font-semibold text-tl-text">Recent Findings</h2>
                  <button
                    onClick={() => setActiveTab('findings')}
                    className="text-xs text-tl-blue hover:underline"
                  >
                    View all
                  </button>
                </div>
                <div className="bg-tl-surface border border-tl-border rounded-lg overflow-hidden">
                  <div className="divide-y divide-tl-border">
                    {findings.slice(0, 8).map((f) => (
                      <Link
                        key={f.id}
                        to={`/projects/${id}/findings/${f.id}`}
                        className="flex items-center gap-3 px-4 py-2.5 hover:bg-tl-surface2 transition-colors group"
                      >
                        <SeverityBadge severity={f.severity} />
                        <span className="flex-1 text-xs text-tl-text2 group-hover:text-tl-text truncate">
                          {f.title}
                        </span>
                        <StatusBadge status={f.status} />
                        <ChevronRight size={13} className="text-tl-muted opacity-0 group-hover:opacity-100 transition-opacity flex-shrink-0" />
                      </Link>
                    ))}
                  </div>
                </div>
              </div>
            )}
          </>
        )}

        {/* ── FINDINGS TAB ── */}
        {activeTab === 'findings' && (
          <FindingsTab projectId={id!} />
        )}

        {/* ── SCANS TAB ── */}
        {activeTab === 'scans' && (
          <ScansTab projectId={id!} scans={scans} />
        )}

        {/* ── REPORTS TAB ── */}
        {activeTab === 'reports' && (
          <ReportsTab projectId={id!} />
        )}
      </div>
    </div>
  )
}

// ─── Inline Findings Tab ───────────────────────────────────────────────────────

function FindingsTab({ projectId }: { projectId: string }) {
  const [severity, setSeverity] = useState('')
  const [status, setStatus] = useState('')
  const [category, setCategory] = useState('')

  const { data: findings = [], isLoading } = useQuery({
    queryKey: ['findings', projectId, { severity, status, category }],
    queryFn: () =>
      findingsApi.list(projectId, {
        severity: severity || undefined,
        status: status || undefined,
        category: category || undefined,
      }),
  })

  const SEVERITIES = ['', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']
  const STATUSES = ['', 'DETECTED', 'VALIDATING', 'CONFIRMED', 'REJECTED', 'REMEDIATION', 'RESOLVED']
  const CATEGORIES = ['', 'secrets', 'injection', 'xss', 'headers', 'api_security', 'configuration', 'cryptography', 'dependencies', 'authentication', 'authorization']

  return (
    <div className="space-y-4">
      {/* Filters */}
      <div className="flex flex-wrap gap-2">
        {([
          ['Severity', severity, setSeverity, SEVERITIES],
          ['Status',   status,   setStatus,   STATUSES],
          ['Category', category, setCategory, CATEGORIES],
        ] as [string, string, (v: string) => void, string[]][]).map(([label, val, set, opts]) => (
          <div key={label} className="flex items-center gap-1.5">
            <span className="text-xs text-tl-muted">{label}:</span>
            <select
              value={val}
              onChange={(e) => set(e.target.value)}
              className="bg-tl-surface border border-tl-border rounded-md px-2 py-1 text-xs text-tl-text2 focus:outline-none focus:border-tl-blue"
            >
              {opts.map((o) => (
                <option key={o} value={o}>{o === '' ? 'All' : o}</option>
              ))}
            </select>
          </div>
        ))}
      </div>

      {/* Table */}
      <div className="bg-tl-surface border border-tl-border rounded-lg overflow-hidden">
        {isLoading ? (
          <div className="flex items-center justify-center py-12">
            <Loader2 size={16} className="animate-spin text-tl-muted" />
          </div>
        ) : findings.length === 0 ? (
          <EmptyState
            icon={ShieldAlert}
            title="No findings match your filters"
            description="Run a scan to detect security issues, or adjust your filters."
          />
        ) : (
          <table className="w-full">
            <thead>
              <tr className="border-b border-tl-border">
                {['Severity', 'Finding', 'Confidence', 'Status', 'Location', 'Scanner'].map((h) => (
                  <th key={h} className="px-4 py-2.5 text-left text-[10px] font-semibold text-tl-muted uppercase tracking-wider">
                    {h}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody className="divide-y divide-tl-border">
              {findings.map((f) => (
                <Link
                  key={f.id}
                  to={`/projects/${projectId}/findings/${f.id}`}
                  className="contents"
                >
                  <tr className="hover:bg-tl-surface2 transition-colors cursor-pointer group">
                    <td className="px-4 py-2.5">
                      <SeverityBadge severity={f.severity} />
                    </td>
                    <td className="px-4 py-2.5 max-w-xs">
                      <span className="text-xs text-tl-text2 group-hover:text-tl-text line-clamp-1">
                        {f.title}
                      </span>
                      <div className="text-[10px] text-tl-muted mt-0.5 font-mono">
                        {f.category}
                      </div>
                    </td>
                    <td className="px-4 py-2.5">
                      <ConfidenceBadge confidence={f.confidence} />
                    </td>
                    <td className="px-4 py-2.5">
                      <StatusBadge status={f.status} />
                    </td>
                    <td className="px-4 py-2.5 max-w-[160px]">
                      <span className="text-[10px] text-tl-muted font-mono truncate block">
                        {f.affected_endpoint
                          ? f.affected_endpoint.replace(/^https?:\/\/[^/]+/, '')
                          : f.affected_file
                          ? f.affected_file.split('/').pop()
                          : f.affected_component ?? '—'}
                      </span>
                    </td>
                    <td className="px-4 py-2.5">
                      <span className="text-[10px] text-tl-muted font-mono">
                        {f.scanner_id.split('.')[0]}
                      </span>
                    </td>
                  </tr>
                </Link>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  )
}

// ─── Inline Reports Tab ───────────────────────────────────────────────────────

function ReportsTab({ projectId }: { projectId: string }) {
  const queryClient = useQueryClient()
  const [generating, setGenerating] = useState(false)
  const [genError, setGenError] = useState<string | null>(null)

  const { data: reports = [], isLoading } = useQuery({
    queryKey: ['reports', projectId],
    queryFn: () => reportsApi.list(projectId),
  })

  const generateMutation = useMutation({
    mutationFn: () => reportsApi.generate(projectId),
    onSuccess: () => {
      setGenerating(false)
      queryClient.invalidateQueries({ queryKey: ['reports', projectId] })
    },
    onError: (err: Error) => {
      setGenerating(false)
      setGenError(err.message)
    },
  })

  const handleGenerate = () => {
    setGenError(null)
    setGenerating(true)
    generateMutation.mutate()
  }

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <h2 className="text-sm font-semibold text-tl-text">Security Reports</h2>
        <button
          onClick={handleGenerate}
          disabled={generating || generateMutation.isPending}
          className="flex items-center gap-1.5 px-3 py-1.5 rounded-md bg-tl-blue text-white text-xs font-medium hover:bg-blue-500 disabled:opacity-60 transition-colors"
        >
          {generating || generateMutation.isPending ? (
            <Loader2 size={12} className="animate-spin" />
          ) : (
            <FileText size={12} />
          )}
          Generate PDF Report
        </button>
      </div>

      {genError && (
        <div className="flex items-start gap-2 px-4 py-3 rounded-lg bg-red-500 bg-opacity-10 border border-red-500 border-opacity-30 text-sm text-red-400">
          <AlertCircle size={14} className="flex-shrink-0 mt-0.5" />
          <span className="text-xs">{genError}</span>
          <button onClick={() => setGenError(null)} className="ml-auto"><X size={13} /></button>
        </div>
      )}

      <div className="bg-tl-surface border border-tl-border rounded-lg overflow-hidden">
        {isLoading ? (
          <div className="flex items-center justify-center py-12">
            <Loader2 size={16} className="animate-spin text-tl-muted" />
          </div>
        ) : reports.length === 0 ? (
          <EmptyState
            icon={FileText}
            title="No reports yet"
            description='Click "Generate PDF Report" to create a professional security assessment report.'
          />
        ) : (
          <div className="divide-y divide-tl-border">
            {reports.map((report) => {
              const meta = report.metadata_json
                ? (() => { try { return JSON.parse(report.metadata_json) } catch { return null } })()
                : null
              return (
                <div key={report.id} className="flex items-center gap-4 px-4 py-3">
                  <FileText size={15} className="text-tl-muted flex-shrink-0" />
                  <div className="flex-1 min-w-0">
                    <div className="text-xs font-medium text-tl-text2 truncate">{report.title}</div>
                    <div className="flex items-center gap-2 text-[10px] text-tl-muted mt-0.5">
                      <span>{formatDate(report.created_at)}</span>
                      {meta?.finding_count != null && (
                        <>
                          <span>·</span>
                          <span>{meta.finding_count} finding{meta.finding_count !== 1 ? 's' : ''}</span>
                        </>
                      )}
                      <span>·</span>
                      <span className="uppercase font-mono">{report.format}</span>
                    </div>
                  </div>
                  <a
                    href={reportsApi.downloadUrl(projectId, report.id)}
                    download
                    className="flex items-center gap-1.5 px-2.5 py-1.5 rounded border border-tl-border text-xs text-tl-text2 hover:bg-tl-surface2 hover:border-tl-blue transition-colors"
                  >
                    <FileDown size={12} />
                    Download
                  </a>
                </div>
              )
            })}
          </div>
        )}
      </div>
    </div>
  )
}

// ─── Inline Scans Tab ─────────────────────────────────────────────────────────

function ScansTab({ projectId, scans }: { projectId: string; scans: ReturnType<typeof useQuery>['data'] & any[] }) {
  if (scans.length === 0) {
    return (
      <EmptyState
        icon={Activity}
        title="No scans yet"
        description='Click "Start Scan" at the top of the page to run your first security scan.'
      />
    )
  }

  return (
    <div className="bg-tl-surface border border-tl-border rounded-lg overflow-hidden">
      <div className="divide-y divide-tl-border">
        {scans.map((scan: any) => {
          const summary = scan.summary ? (() => { try { return JSON.parse(scan.summary) } catch { return null } })() : null
          const config = scan.scanner_config ? (() => { try { return JSON.parse(scan.scanner_config) } catch { return null } })() : null
          return (
            <Link
              key={scan.id}
              to={`/projects/${projectId}/scans/${scan.id}`}
              className="flex items-start gap-4 px-4 py-3 hover:bg-tl-surface2 transition-colors group"
            >
              <div className="flex-1 min-w-0">
                <div className="flex items-center gap-2 mb-1">
                  <ScanStatusChip status={scan.status} />
                  <span className="text-xs text-tl-muted font-mono">{scan.id.slice(0, 8)}…</span>
                </div>
                <div className="flex items-center gap-3 text-xs text-tl-muted">
                  <span>{formatDate(scan.created_at)}</span>
                  {summary && (
                    <>
                      <span className="text-tl-border">·</span>
                      <span>{summary.total_confirmed ?? 0} confirmed finding{(summary.total_confirmed ?? 0) !== 1 ? 's' : ''}</span>
                      <span className="text-tl-border">·</span>
                      <span>{summary.scanner_count ?? 0} scanner{(summary.scanner_count ?? 0) !== 1 ? 's' : ''}</span>
                    </>
                  )}
                  {scan.error_message && (
                    <span className="text-red-400 truncate max-w-xs">{scan.error_message}</span>
                  )}
                </div>
                {scan.scanner_results && scan.scanner_results.length > 0 && (
                  <div className="flex flex-wrap gap-1 mt-1.5">
                    {scan.scanner_results.map((sr: any) => (
                      <span key={sr.id} className={`text-[10px] font-mono px-1.5 py-0.5 rounded border ${
                        sr.status === 'failed'
                          ? 'border-red-500 border-opacity-30 text-red-400 bg-red-500 bg-opacity-10'
                          : 'border-tl-border text-tl-muted bg-tl-surface2'
                      }`}>
                        {sr.scanner_id.split('.').pop()} ({sr.confirmed_finding_count})
                      </span>
                    ))}
                  </div>
                )}
              </div>
              <ChevronRight size={14} className="text-tl-muted opacity-0 group-hover:opacity-100 transition-opacity flex-shrink-0 mt-1" />
            </Link>
          )
        })}
      </div>
    </div>
  )
}
