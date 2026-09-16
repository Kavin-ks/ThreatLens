import { useState } from 'react'
import { Link } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import { Activity, CheckCircle2, XCircle, Clock, Loader2 } from 'lucide-react'
import { TopBar } from '../components/layout/TopBar'
import { EmptyState } from '../components/common/EmptyState'
import { formatRelative } from '../lib/utils'
import { globalScansApi, projectsApi } from '../api/endpoints'
import { cn } from '../lib/utils'
import type { ScanRun } from '../types'

const STATUS_CONFIG: Record<string, { icon: React.ComponentType<{ size?: number; className?: string }>; color: string; label: string }> = {
  completed: { icon: CheckCircle2, color: 'text-emerald-400', label: 'Completed' },
  failed: { icon: XCircle, color: 'text-red-400', label: 'Failed' },
  running: { icon: Loader2, color: 'text-tl-blue', label: 'Running' },
  pending: { icon: Clock, color: 'text-amber-400', label: 'Pending' },
  cancelled: { icon: XCircle, color: 'text-tl-muted', label: 'Cancelled' },
}

const SCAN_STATUSES = ['pending', 'running', 'completed', 'failed', 'cancelled']

function ScanRow({
  scan,
  projectName,
}: {
  scan: ScanRun
  projectName: string
}) {
  const cfg = STATUS_CONFIG[scan.status] ?? STATUS_CONFIG.pending
  const Icon = cfg.icon
  let summary: { total_raw?: number; total_confirmed?: number } = {}
  try { summary = JSON.parse(scan.summary ?? '{}') } catch {}

  return (
    <Link
      to={`/projects/${scan.project_id}/scans/${scan.id}`}
      className="flex items-center gap-4 px-4 py-3 hover:bg-tl-surface2 transition-colors group border-b border-tl-border last:border-b-0"
    >
      <Icon
        size={15}
        className={cn(cfg.color, scan.status === 'running' && 'animate-spin')}
      />
      <div className="flex-1 min-w-0">
        <div className="flex items-center gap-2">
          <span className="text-sm font-medium text-tl-text2 group-hover:text-tl-text">
            {projectName}
          </span>
          <span className="text-xs text-tl-muted font-mono">{scan.id.slice(0, 8)}</span>
        </div>
        <div className="flex items-center gap-3 text-xs text-tl-muted mt-0.5">
          <span className={cfg.color}>{cfg.label}</span>
          {summary.total_raw !== undefined && (
            <>
              <span className="text-tl-border">·</span>
              <span>{summary.total_raw} findings</span>
            </>
          )}
          <span className="text-tl-border">·</span>
          <span>{formatRelative(scan.created_at)}</span>
        </div>
      </div>
    </Link>
  )
}

export default function GlobalScans() {
  const [statusFilter, setStatusFilter] = useState('')
  const [projectId, setProjectId] = useState('')

  const { data: scans = [], isLoading } = useQuery({
    queryKey: ['global-scans', { statusFilter, projectId }],
    queryFn: () =>
      globalScansApi.list({
        status: statusFilter || undefined,
        project_id: projectId || undefined,
      }),
  })

  const { data: projects = [] } = useQuery({
    queryKey: ['projects'],
    queryFn: projectsApi.list,
  })

  const projectMap = Object.fromEntries(projects.map((p) => [p.id, p.name]))

  return (
    <div className="flex flex-col h-full">
      <TopBar title="Scans" subtitle="Scan history across all projects" />

      <div className="flex-1 overflow-y-auto p-6 space-y-4">
        {/* Filters */}
        <div className="flex flex-wrap gap-2">
          <select
            value={statusFilter}
            onChange={(e) => setStatusFilter(e.target.value)}
            className="text-sm bg-tl-surface border border-tl-border rounded-md px-2 py-1.5 text-tl-text focus:outline-none focus:ring-1 focus:ring-tl-blue"
          >
            <option value="">All statuses</option>
            {SCAN_STATUSES.map((s) => (
              <option key={s} value={s}>{s.charAt(0).toUpperCase() + s.slice(1)}</option>
            ))}
          </select>

          <select
            value={projectId}
            onChange={(e) => setProjectId(e.target.value)}
            className="text-sm bg-tl-surface border border-tl-border rounded-md px-2 py-1.5 text-tl-text focus:outline-none focus:ring-1 focus:ring-tl-blue"
          >
            <option value="">All projects</option>
            {projects.map((p) => (
              <option key={p.id} value={p.id}>{p.name}</option>
            ))}
          </select>
        </div>

        <div className="text-xs text-tl-muted">
          {isLoading ? 'Loading…' : `${scans.length} scan${scans.length !== 1 ? 's' : ''}`}
        </div>

        <div className="bg-tl-surface border border-tl-border rounded-lg overflow-hidden">
          {isLoading ? (
            <div className="py-12 text-center text-sm text-tl-muted">Loading scans…</div>
          ) : scans.length === 0 ? (
            <EmptyState
              icon={Activity}
              title="No scans match your filters"
              description="Trigger a scan from a project to see it here."
            />
          ) : (
            <div>
              {scans.map((s) => (
                <ScanRow key={s.id} scan={s} projectName={projectMap[s.project_id] ?? s.project_id} />
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  )
}
