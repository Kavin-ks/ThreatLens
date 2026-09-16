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
} from 'lucide-react'
import { TopBar } from '../components/layout/TopBar'
import { EmptyState } from '../components/common/EmptyState'
import { SeverityBadge } from '../components/common/SeverityBadge'
import { formatRelative } from '../lib/utils'
import { projectsApi } from '../api/endpoints'
import type { ProjectSummary } from '../types'

function StatCard({
  label,
  value,
  icon: Icon,
  iconClass = 'text-tl-muted',
  note,
}: {
  label: string
  value: string | number
  icon: React.ComponentType<{ size?: number; className?: string }>
  iconClass?: string
  note?: string
}) {
  return (
    <div className="bg-tl-surface border border-tl-border rounded-lg p-4">
      <div className="flex items-start justify-between mb-3">
        <span className="text-xs font-medium text-tl-muted uppercase tracking-wide">{label}</span>
        <Icon size={15} className={iconClass} />
      </div>
      <div className="text-2xl font-semibold font-mono text-tl-text">{value}</div>
      {note && <div className="text-xs text-tl-muted mt-1">{note}</div>}
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
          {project.critical_count > 0 && (
            <SeverityBadge severity="CRITICAL" />
          )}
          {project.critical_count === 0 && project.high_count > 0 && (
            <SeverityBadge severity="HIGH" />
          )}
        </div>
        <div className="flex items-center gap-3 mt-0.5">
          <span className="text-xs text-tl-muted">
            {project.total_findings} finding{project.total_findings !== 1 ? 's' : ''}
          </span>
          {project.last_scan_at && (
            <>
              <span className="text-tl-border">·</span>
              <span className="text-xs text-tl-muted">
                Last scan {formatRelative(project.last_scan_at)}
              </span>
            </>
          )}
        </div>
      </div>
      <ArrowRight size={14} className="text-tl-muted opacity-0 group-hover:opacity-100 transition-opacity flex-shrink-0" />
    </Link>
  )
}

export default function Dashboard() {
  const { data: projects = [], isLoading, isError } = useQuery({
    queryKey: ['projects'],
    queryFn: projectsApi.list,
  })

  const totalFindings = projects.reduce((s, p) => s + p.total_findings, 0)
  const confirmedFindings = projects.reduce((s, p) => s + p.confirmed_findings, 0)
  const criticalCount = projects.reduce((s, p) => s + p.critical_count, 0)

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
        {/* Stats row */}
        <div className="grid grid-cols-2 lg:grid-cols-4 gap-3">
          <StatCard
            label="Projects"
            value={projects.length}
            icon={FolderOpen}
            iconClass="text-tl-blue"
          />
          <StatCard
            label="Total Findings"
            value={totalFindings}
            icon={ShieldAlert}
            iconClass="text-tl-muted"
            note={totalFindings === 0 ? 'Run a scan to see findings' : undefined}
          />
          <StatCard
            label="Critical"
            value={criticalCount}
            icon={AlertTriangle}
            iconClass={criticalCount > 0 ? 'text-red-400' : 'text-tl-muted'}
          />
          <StatCard
            label="Confirmed"
            value={confirmedFindings}
            icon={CheckCircle2}
            iconClass={confirmedFindings > 0 ? 'text-emerald-400' : 'text-tl-muted'}
          />
        </div>

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
            {isLoading ? (
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
                description="Create your first security assessment project to get started. Point ThreatLens at a target repository or application."
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

        {/* Quick start */}
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
