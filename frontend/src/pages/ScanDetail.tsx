import { Link, useParams } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import {
  ArrowLeft,
  Loader2,
  AlertCircle,
  CheckCircle2,
  Clock,
  XCircle,
  ShieldAlert,
  ChevronRight,
} from 'lucide-react'
import { TopBar } from '../components/layout/TopBar'
import { SeverityBadge } from '../components/common/SeverityBadge'
import { EmptyState } from '../components/common/EmptyState'
import { scansApi, findingsApi } from '../api/endpoints'
import { formatDate, formatRelative } from '../lib/utils'
import type { ScanStatus, ScannerResult } from '../types'

function ScanStatusIcon({ status }: { status: ScanStatus }) {
  if (status === 'running' || status === 'pending')
    return <Loader2 size={16} className="animate-spin text-tl-blue" />
  if (status === 'completed')
    return <CheckCircle2 size={16} className="text-emerald-400" />
  if (status === 'failed')
    return <XCircle size={16} className="text-red-400" />
  return <Clock size={16} className="text-tl-muted" />
}

function ScanStatusLabel({ status }: { status: ScanStatus }) {
  const cfg: Record<ScanStatus, { label: string; cls: string }> = {
    pending:   { label: 'Pending',   cls: 'text-tl-muted' },
    running:   { label: 'Running…',  cls: 'text-tl-blue' },
    completed: { label: 'Completed', cls: 'text-emerald-400' },
    failed:    { label: 'Failed',    cls: 'text-red-400' },
    cancelled: { label: 'Cancelled', cls: 'text-tl-muted' },
  }
  const { label, cls } = cfg[status] ?? cfg.pending
  return <span className={`text-sm font-medium ${cls}`}>{label}</span>
}

function ScannerResultRow({ result }: { result: ScannerResult }) {
  const isOk = result.status === 'completed'
  const isFailed = result.status === 'failed'
  return (
    <tr className="border-b border-tl-border last:border-0">
      <td className="px-4 py-2.5">
        <span className="text-xs font-mono text-tl-text2">{result.scanner_id}</span>
      </td>
      <td className="px-4 py-2.5">
        <span className={`text-xs font-medium ${
          isFailed ? 'text-red-400' : isOk ? 'text-emerald-400' : 'text-tl-blue'
        }`}>
          {result.status}
        </span>
      </td>
      <td className="px-4 py-2.5 text-center">
        <span className="text-xs font-mono text-tl-text2">{result.raw_finding_count}</span>
      </td>
      <td className="px-4 py-2.5 text-center">
        <span className="text-xs font-mono text-tl-text2">{result.confirmed_finding_count}</span>
      </td>
      <td className="px-4 py-2.5">
        <span className="text-xs font-mono text-tl-muted">
          {result.duration_ms != null ? `${result.duration_ms}ms` : '—'}
        </span>
      </td>
      <td className="px-4 py-2.5 max-w-xs">
        {result.error_message && (
          <span className="text-xs text-red-400 truncate block">{result.error_message}</span>
        )}
      </td>
    </tr>
  )
}

export default function ScanDetail() {
  const { id: projectId, scanId } = useParams<{ id: string; scanId: string }>()

  const { data: scan, isLoading, isError } = useQuery({
    queryKey: ['scan', projectId, scanId],
    queryFn: () => scansApi.get(projectId!, scanId!),
    enabled: !!(projectId && scanId),
    refetchInterval: (query) => {
      const s = query.state.data?.status
      return s === 'pending' || s === 'running' ? 2000 : false
    },
  })

  const { data: findings = [] } = useQuery({
    queryKey: ['findings', projectId, { scan_id: scanId }],
    queryFn: () => findingsApi.list(projectId!, { scan_id: scanId }),
    enabled: !!(projectId && scanId && scan?.status === 'completed'),
  })

  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-full">
        <Loader2 size={20} className="animate-spin text-tl-muted" />
      </div>
    )
  }

  if (isError || !scan) {
    return (
      <div className="flex flex-col items-center justify-center h-full gap-3">
        <AlertCircle size={24} className="text-red-400" />
        <p className="text-sm text-tl-muted">Scan not found.</p>
        <Link to={`/projects/${projectId}`} className="text-xs text-tl-blue hover:underline">
          Back to project
        </Link>
      </div>
    )
  }

  const summary = scan.summary
    ? (() => { try { return JSON.parse(scan.summary) } catch { return null } })()
    : null

  const isActive = scan.status === 'pending' || scan.status === 'running'

  return (
    <div className="flex flex-col h-full">
      <TopBar
        title="Scan Run"
        subtitle={`${scan.id.slice(0, 8)}… · Started ${formatRelative(scan.created_at)}`}
        actions={
          <Link
            to={`/projects/${projectId}`}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-md text-tl-muted hover:text-tl-text2 hover:bg-tl-surface2 text-xs transition-colors"
          >
            <ArrowLeft size={13} />
            Back to Project
          </Link>
        }
      />

      <div className="flex-1 overflow-y-auto p-6 space-y-6">
        {/* Status card */}
        <div className="bg-tl-surface border border-tl-border rounded-lg p-5">
          <div className="flex items-center gap-3 mb-4">
            <ScanStatusIcon status={scan.status} />
            <ScanStatusLabel status={scan.status} />
            {isActive && (
              <span className="text-xs text-tl-muted">Checking status every 2 s…</span>
            )}
          </div>

          {scan.error_message && (
            <div className="flex items-start gap-2 px-4 py-3 rounded-lg bg-red-500 bg-opacity-10 border border-red-500 border-opacity-30 text-sm text-red-400 mb-4">
              <AlertCircle size={15} className="flex-shrink-0 mt-0.5" />
              <span className="font-mono text-xs">{scan.error_message}</span>
            </div>
          )}

          {summary && (
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
              {[
                { label: 'Scanners Run', value: summary.scanner_count ?? 0 },
                { label: 'Raw Findings', value: summary.total_raw ?? 0 },
                { label: 'Confirmed', value: summary.total_confirmed ?? 0 },
                {
                  label: 'Critical + High',
                  value: (summary.by_severity?.CRITICAL ?? 0) + (summary.by_severity?.HIGH ?? 0),
                },
              ].map(({ label, value }) => (
                <div key={label} className="text-center">
                  <div className="text-xl font-semibold font-mono text-tl-text">{value}</div>
                  <div className="text-[10px] text-tl-muted uppercase tracking-wider mt-0.5">{label}</div>
                </div>
              ))}
            </div>
          )}

          <div className="mt-4 text-xs text-tl-muted">
            Started: {formatDate(scan.created_at)}
            {!isActive && (
              <>
                {' · '}Updated: {formatDate(scan.updated_at)}
              </>
            )}
          </div>
        </div>

        {/* Scanner breakdown */}
        {(scan.scanner_results ?? []).length > 0 && (
          <div>
            <h2 className="text-sm font-semibold text-tl-text mb-3">Scanner Breakdown</h2>
            <div className="bg-tl-surface border border-tl-border rounded-lg overflow-hidden">
              <table className="w-full">
                <thead>
                  <tr className="border-b border-tl-border">
                    {['Scanner', 'Status', 'Raw', 'Confirmed', 'Duration', 'Error'].map((h) => (
                      <th key={h} className="px-4 py-2.5 text-left text-[10px] font-semibold text-tl-muted uppercase tracking-wider">
                        {h}
                      </th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {scan.scanner_results.map((r) => (
                    <ScannerResultRow key={r.id} result={r} />
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        )}

        {/* Findings from this scan */}
        {scan.status === 'completed' && (
          <div>
            <div className="flex items-center justify-between mb-3">
              <h2 className="text-sm font-semibold text-tl-text">
                Findings ({findings.length})
              </h2>
              {findings.length > 0 && (
                <Link
                  to={`/projects/${projectId}`}
                  className="text-xs text-tl-blue hover:underline"
                >
                  View in project
                </Link>
              )}
            </div>
            <div className="bg-tl-surface border border-tl-border rounded-lg overflow-hidden">
              {findings.length === 0 ? (
                <EmptyState
                  icon={ShieldAlert}
                  title="No findings detected"
                  description="This scan did not detect any security issues."
                />
              ) : (
                <div className="divide-y divide-tl-border">
                  {findings.map((f) => (
                    <Link
                      key={f.id}
                      to={`/projects/${projectId}/findings/${f.id}`}
                      className="flex items-center gap-3 px-4 py-2.5 hover:bg-tl-surface2 transition-colors group"
                    >
                      <SeverityBadge severity={f.severity} />
                      <div className="flex-1 min-w-0">
                        <div className="text-xs text-tl-text2 group-hover:text-tl-text truncate">
                          {f.title}
                        </div>
                        <div className="text-[10px] text-tl-muted font-mono mt-0.5">
                          {f.affected_endpoint
                            ? f.affected_endpoint.replace(/^https?:\/\/[^/]+/, '')
                            : f.affected_file?.split('/').pop()
                            ?? f.affected_component
                            ?? f.category}
                        </div>
                      </div>
                      <ChevronRight size={13} className="text-tl-muted opacity-0 group-hover:opacity-100 transition-opacity flex-shrink-0" />
                    </Link>
                  ))}
                </div>
              )}
            </div>
          </div>
        )}
      </div>
    </div>
  )
}
