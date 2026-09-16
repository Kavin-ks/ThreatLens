import { useQuery } from '@tanstack/react-query'
import { Link } from 'react-router-dom'
import {
  FolderOpen,
  ShieldAlert,
  Plus,
  ArrowRight,
  AlertTriangle,
  CheckCircle2,
  Clock,
  Scan,
  Activity,
  TrendingUp,
} from 'lucide-react'
import { TopBar } from '../components/layout/TopBar'
import { EmptyState } from '../components/common/EmptyState'
import { SeverityBadge } from '../components/common/SeverityBadge'
import { formatRelative } from '../lib/utils'
import { projectsApi, dashboardApi } from '../api/endpoints'
import type { ProjectSummary } from '../types'

function StatCard({
  label,
  value,
  icon: Icon,
  iconClass = 'text-tl-muted',
  note,
  to,
}: {
  label: string
  value: string | number
  icon: React.ComponentType<{ size?: number; className?: string }>
  iconClass?: string
  note?: string
  to?: string
}) {
  const inner = (
    <div className="bg-tl-surface border border-tl-border rounded-lg p-4 hover:border-tl-border2 transition-colors">
      <div className="flex items-start justify-between mb-3">
        <span className="text-xs font-medium text-tl-muted uppercase tracking-wide">{label}</span>
        <Icon size={15} className={iconClass} />
      </div>
      <div className="text-2xl font-semibold font-mono text-tl-text">{value}</div>
      {note && <div className="text-xs text-tl-muted mt-1">{note}</div>}
    </div>
  )
  return to ? <Link to={to}>{inner}</Link> : <div>{inner}</div>
}

function SeverityBar({
  dist,
}: {
  dist: { CRITICAL: number; HIGH: number; MEDIUM: number; LOW: number; INFO: number }
}) {
  const total = Object.values(dist).reduce((a, b) => a + b, 0)
  if (total === 0) return null

  const segments = [
    { key: 'CRITICAL', color: 'bg-red-500', label: 'Critical' },
    { key: 'HIGH', color: 'bg-orange-400', label: 'High' },
    { key: 'MEDIUM', color: 'bg-amber-400', label: 'Medium' },
    { key: 'LOW', color: 'bg-blue-400', label: 'Low' },
    { key: 'INFO', color: 'bg-tl-muted', label: 'Info' },
  ] as const

  return (
    <div className="bg-tl-surface border border-tl-border rounded-lg p-4">
      <div className="flex items-center gap-2 mb-3">
        <TrendingUp size={14} className="text-tl-muted" />
        <span className="text-xs font-medium text-tl-muted uppercase tracking-wide">
          Severity Distribution
        </span>
      </div>
      <div className="flex rounded-full overflow-hidden h-2.5 mb-3">
        {segments.map(({ key, color }) => {
          const pct = total > 0 ? (dist[key] / total) * 100 : 0
          return pct > 0 ? (
            <div key={key} className={`${color} transition-all`} style={{ width: `${pct}%` }} />
          ) : null
        })}
      </div>
      <div className="flex flex-wrap gap-3">
        {segments.map(({ key, color, label }) =>
          dist[key] > 0 ? (
            <div key={key} className="flex items-center gap-1.5 text-xs text-tl-muted">
              <div className={`w-2 h-2 rounded-full ${color}`} />
              <span>{label}: {dist[key]}</span>
            </div>
          ) : null
        )}
      </div>
    </div>
  )
}

function StatusBreakdown({ dist }: { dist: Record<string, number> }) {
  const order = ['DETECTED', 'VALIDATING', 'CONFIRMED', 'REMEDIATION', 'RETESTING', 'RESOLVED', 'REJECTED']
  const colors: Record<string, string> = {
    DETECTED: 'text-tl-muted',
    VALIDATING: 'text-amber-400',
    CONFIRMED: 'text-red-400',
    REMEDIATION: 'text-blue-400',
    RETESTING: 'text-purple-400',
    RESOLVED: 'text-emerald-400',
    REJECTED: 'text-tl-muted',
  }
  const entries = order.filter((s) => (dist[s] ?? 0) > 0)
  if (entries.length === 0) return null

  return (
    <div className="bg-tl-surface border border-tl-border rounded-lg p-4">
      <div className="flex items-center gap-2 mb-3">
        <Activity size={14} className="text-tl-muted" />
        <span className="text-xs font-medium text-tl-muted uppercase tracking-wide">
          Findings by Status
        </span>
      </div>
      <div className="space-y-1.5">
        {entries.map((s) => {
          const count = dist[s] ?? 0
          const total = Object.values(dist).reduce((a, b) => a + b, 0)
          const pct = total > 0 ? Math.round((count / total) * 100) : 0
          return (
            <div key={s} className="flex items-center gap-2">
              <span className={`text-xs w-24 ${colors[s] ?? 'text-tl-muted'}`}>{s}</span>
              <div className="flex-1 h-1.5 bg-tl-surface2 rounded-full overflow-hidden">
                <div
                  className="h-full bg-tl-blue bg-opacity-50 rounded-full transition-all"
                  style={{ width: `${pct}%` }}
                />
              </div>
              <span className="text-xs text-tl-muted w-8 text-right font-mono">{count}</span>
            </div>
          )
        })}
      </div>
    </div>
  )
}

function ProjectRow({ project }: { project: ProjectSummary }) {
  return (
    <Link
      to={`/projects/${project.id}`}
      className="flex items-center gap-4 px-4 py-3 hover:bg-tl-surface2 transition-colors group"
    >
      <div className="flex-shrink-0 w-8 h-8 rounded-lg bg-tl-blue bg-opacity-10 border border-tl-blue border-opacity-20 flex items-center justify-center">
        <FolderOpen size={14} className="text-tl-blue opacity-70" />
      </div>
      <div className="flex-1 min-w-0">
        <div className="flex items-center gap-2">
          <span className="text-sm font-medium text-tl-text2 group-hover:text-tl-text truncate">
            {project.name}
          </span>
          {project.critical_count > 0 && <SeverityBadge severity="CRITICAL" />}
          {project.critical_count === 0 && project.high_count > 0 && <SeverityBadge severity="HIGH" />}
        </div>
        <div className="flex items-center gap-3 mt-0.5">
          <span className="text-xs text-tl-muted">
            {project.total_findings} finding{project.total_findings !== 1 ? 's' : ''}
          </span>
          {project.last_scan_at && (
            <>
              <span className="text-tl-border">·</span>
              <span className="text-xs text-tl-muted">Last scan {formatRelative(project.last_scan_at)}</span>
            </>
          )}
        </div>
      </div>
      <ArrowRight size={14} className="text-tl-muted opacity-0 group-hover:opacity-100 transition-opacity flex-shrink-0" />
    </Link>
  )
}

export default function Dashboard() {
  const { data: projects = [], isLoading: projectsLoading, isError } = useQuery({
    queryKey: ['projects'],
    queryFn: projectsApi.list,
  })

  const { data: stats } = useQuery({
    queryKey: ['dashboard-stats'],
    queryFn: dashboardApi.stats,
    refetchInterval: 30_000,
  })

  return (
    <div className="flex flex-col h-full">
      <TopBar
        title="Dashboard"
        subtitle="Security assessment overview"
        actions={
          <Link
            to="/projects/new"
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-md bg-tl-blue text-white text-xs font-medium hover:bg-tl-blue2 transition-colors"
          >
            <Plus size={13} />
            New Assessment
          </Link>
        }
      />

      <div className="flex-1 overflow-y-auto p-6 space-y-6">
        {/* Stats row — sourced from real DB stats */}
        <div className="grid grid-cols-2 lg:grid-cols-4 gap-3">
          <StatCard
            label="Projects"
            value={stats?.total_projects ?? projects.length}
            icon={FolderOpen}
            iconClass="text-tl-blue"
            to="/projects"
          />
          <StatCard
            label="Total Findings"
            value={stats?.total_findings ?? 0}
            icon={ShieldAlert}
            iconClass="text-tl-muted"
            note={stats?.total_findings === 0 ? 'Run a scan to see findings' : undefined}
            to="/findings"
          />
          <StatCard
            label="Critical"
            value={stats?.critical_findings ?? 0}
            icon={AlertTriangle}
            iconClass={(stats?.critical_findings ?? 0) > 0 ? 'text-red-400' : 'text-tl-muted'}
          />
          <StatCard
            label="Confirmed"
            value={stats?.confirmed_findings ?? 0}
            icon={CheckCircle2}
            iconClass={(stats?.confirmed_findings ?? 0) > 0 ? 'text-emerald-400' : 'text-tl-muted'}
            note={stats?.resolved_findings ? `${stats.resolved_findings} resolved` : undefined}
          />
        </div>

        {/* Charts row */}
        {stats && (
          <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
            <SeverityBar dist={stats.severity_distribution} />
            <StatusBreakdown dist={stats.status_distribution} />
          </div>
        )}

        {/* Secondary stats */}
        {stats && (
          <div className="grid grid-cols-2 lg:grid-cols-4 gap-3">
            <StatCard
              label="Total Scans"
              value={stats.total_scans}
              icon={Scan}
              iconClass="text-tl-muted"
              to="/scans"
            />
            <StatCard
              label="Running"
              value={stats.running_scans}
              icon={Activity}
              iconClass={stats.running_scans > 0 ? 'text-tl-blue' : 'text-tl-muted'}
            />
            <StatCard
              label="Scans (7d)"
              value={stats.recent_scans_count}
              icon={Clock}
              iconClass="text-tl-muted"
            />
            <StatCard
              label="Resolved"
              value={stats.resolved_findings}
              icon={CheckCircle2}
              iconClass={stats.resolved_findings > 0 ? 'text-emerald-400' : 'text-tl-muted'}
            />
          </div>
        )}

        {/* Projects */}
        <div>
          <div className="flex items-center justify-between mb-3">
            <h2 className="text-sm font-semibold text-tl-text">Assessment Projects</h2>
            {projects.length > 0 && (
              <Link to="/projects" className="text-xs text-tl-blue hover:underline">
                View all
              </Link>
            )}
          </div>

          <div className="bg-tl-surface border border-tl-border rounded-lg overflow-hidden">
            {projectsLoading ? (
              <div className="flex items-center justify-center py-12">
                <div className="flex items-center gap-2 text-tl-muted text-sm">
                  <Scan size={16} className="animate-spin" />
                  Loading projects…
                </div>
              </div>
            ) : isError ? (
              <div className="py-12 text-center text-sm text-red-400">
                Failed to load projects. Is the backend running?
              </div>
            ) : projects.length === 0 ? (
              <EmptyState
                icon={FolderOpen}
                title="No assessment projects yet"
                description="Create your first security assessment project to get started."
                action={
                  <Link
                    to="/projects/new"
                    className="flex items-center gap-1.5 px-4 py-2 rounded-md bg-tl-blue text-white text-sm font-medium hover:bg-tl-blue2 transition-colors"
                  >
                    <Plus size={14} />
                    Create First Assessment
                  </Link>
                }
              />
            ) : (
              <div className="divide-y divide-tl-border">
                {projects.map((p) => (
                  <ProjectRow key={p.id} project={p} />
                ))}
              </div>
            )}
          </div>
        </div>

        {/* Quick start for empty state */}
        {projects.length === 0 && (
          <div>
            <h2 className="text-sm font-semibold text-tl-text mb-3">Quick Start</h2>
            <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
              {[
                {
                  icon: Plus,
                  title: 'Create Assessment',
                  desc: 'Set up a new security assessment project for your target application.',
                  to: '/projects/new',
                },
                {
                  icon: Scan,
                  title: 'Run a Scan',
                  desc: 'Point ThreatLens at a source repository or running application to scan.',
                  to: '/projects/new',
                },
                {
                  icon: Clock,
                  title: 'Review Findings',
                  desc: 'After scanning, review and validate detected vulnerabilities with evidence.',
                  to: '/findings',
                },
              ].map(({ icon: Icon, title, desc, to }) => (
                <Link
                  key={title}
                  to={to}
                  className="block bg-tl-surface border border-tl-border rounded-lg p-4 hover:border-tl-border2 hover:bg-tl-surface2 transition-colors group"
                >
                  <div className="flex items-center gap-2 mb-2">
                    <Icon size={14} className="text-tl-blue" />
                    <span className="text-sm font-medium text-tl-text2 group-hover:text-tl-text">
                      {title}
                    </span>
                  </div>
                  <p className="text-xs text-tl-muted leading-relaxed">{desc}</p>
                </Link>
              ))}
            </div>
          </div>
        )}
      </div>
    </div>
  )
}
