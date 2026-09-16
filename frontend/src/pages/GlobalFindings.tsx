import { useState } from 'react'
import { Link } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import { ShieldAlert, Search, Filter } from 'lucide-react'
import { TopBar } from '../components/layout/TopBar'
import { SeverityBadge } from '../components/common/SeverityBadge'
import { StatusBadge } from '../components/common/StatusBadge'
import { EmptyState } from '../components/common/EmptyState'
import { formatRelative } from '../lib/utils'
import { globalFindingsApi, projectsApi } from '../api/endpoints'
import type { GlobalFindingSummary } from '../types'

const SEVERITIES = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']
const STATUSES = ['DETECTED', 'VALIDATING', 'CONFIRMED', 'REJECTED', 'REMEDIATION', 'RETESTING', 'RESOLVED']

function FindingRow({ finding }: { finding: GlobalFindingSummary }) {
  return (
    <Link
      to={`/projects/${finding.project_id}/findings/${finding.id}`}
      className="flex items-start gap-3 px-4 py-3 hover:bg-tl-surface2 transition-colors group border-b border-tl-border last:border-b-0"
    >
      <div className="flex-1 min-w-0 space-y-1">
        <div className="flex items-center gap-2 flex-wrap">
          <SeverityBadge severity={finding.severity} />
          <StatusBadge status={finding.status} />
          <span className="text-sm font-medium text-tl-text2 group-hover:text-tl-text truncate">
            {finding.title}
          </span>
        </div>
        <div className="flex items-center gap-3 text-xs text-tl-muted">
          <span className="font-mono">{finding.scanner_id}</span>
          {finding.affected_file && (
            <>
              <span className="text-tl-border">·</span>
              <span className="font-mono truncate max-w-xs">{finding.affected_file}</span>
            </>
          )}
          {finding.affected_endpoint && !finding.affected_file && (
            <>
              <span className="text-tl-border">·</span>
              <span className="font-mono truncate max-w-xs">{finding.affected_endpoint}</span>
            </>
          )}
          <span className="text-tl-border">·</span>
          <span>{formatRelative(finding.created_at)}</span>
        </div>
      </div>
    </Link>
  )
}

export default function GlobalFindings() {
  const [search, setSearch] = useState('')
  const [severity, setSeverity] = useState('')
  const [status, setStatus] = useState('')
  const [projectId, setProjectId] = useState('')

  const { data: findings = [], isLoading } = useQuery({
    queryKey: ['global-findings', { search, severity, status, projectId }],
    queryFn: () =>
      globalFindingsApi.list({
        search: search || undefined,
        severity: severity || undefined,
        status: status || undefined,
        project_id: projectId || undefined,
      }),
  })

  const { data: projects = [] } = useQuery({
    queryKey: ['projects'],
    queryFn: projectsApi.list,
  })

  return (
    <div className="flex flex-col h-full">
      <TopBar title="Findings" subtitle="All findings across projects" />

      <div className="flex-1 overflow-y-auto p-6 space-y-4">
        {/* Filters */}
        <div className="flex flex-wrap gap-2">
          <div className="relative flex-1 min-w-48">
            <Search size={13} className="absolute left-3 top-1/2 -translate-y-1/2 text-tl-muted" />
            <input
              type="text"
              placeholder="Search findings…"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              className="w-full pl-8 pr-3 py-1.5 text-sm bg-tl-surface border border-tl-border rounded-md text-tl-text placeholder:text-tl-muted focus:outline-none focus:ring-1 focus:ring-tl-blue"
            />
          </div>

          <div className="flex items-center gap-1.5">
            <Filter size={13} className="text-tl-muted" />
            <select
              value={severity}
              onChange={(e) => setSeverity(e.target.value)}
              className="text-sm bg-tl-surface border border-tl-border rounded-md px-2 py-1.5 text-tl-text focus:outline-none focus:ring-1 focus:ring-tl-blue"
            >
              <option value="">All severities</option>
              {SEVERITIES.map((s) => <option key={s} value={s}>{s}</option>)}
            </select>

            <select
              value={status}
              onChange={(e) => setStatus(e.target.value)}
              className="text-sm bg-tl-surface border border-tl-border rounded-md px-2 py-1.5 text-tl-text focus:outline-none focus:ring-1 focus:ring-tl-blue"
            >
              <option value="">All statuses</option>
              {STATUSES.map((s) => <option key={s} value={s}>{s}</option>)}
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
        </div>

        {/* Count */}
        <div className="text-xs text-tl-muted">
          {isLoading ? 'Loading…' : `${findings.length} finding${findings.length !== 1 ? 's' : ''}`}
        </div>

        {/* Table */}
        <div className="bg-tl-surface border border-tl-border rounded-lg overflow-hidden">
          {isLoading ? (
            <div className="py-12 text-center text-sm text-tl-muted">Loading findings…</div>
          ) : findings.length === 0 ? (
            <EmptyState
              icon={ShieldAlert}
              title="No findings match your filters"
              description="Adjust the filters above or run a security scan to generate findings."
            />
          ) : (
            <div>
              {findings.map((f) => (
                <FindingRow key={f.id} finding={f} />
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  )
}
