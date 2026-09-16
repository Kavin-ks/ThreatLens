import { useQuery } from '@tanstack/react-query'
import { Link } from 'react-router-dom'
import { Plus, FolderOpen, ArrowRight } from 'lucide-react'
import { TopBar } from '../components/layout/TopBar'
import { EmptyState } from '../components/common/EmptyState'
import { SeverityBadge } from '../components/common/SeverityBadge'
import { formatRelative } from '../lib/utils'
import { projectsApi } from '../api/endpoints'

export default function Projects() {
  const { data: projects = [], isLoading } = useQuery({
    queryKey: ['projects'],
    queryFn: projectsApi.list,
  })

  return (
    <div className="flex flex-col h-full">
      <TopBar
        title="Projects"
        subtitle="All security assessment projects"
        actions={
          <Link
            to="/projects/new"
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-md bg-tl-blue text-white text-xs font-medium hover:bg-tl-blue2 transition-colors"
          >
            <Plus size={13} />
            New Project
          </Link>
        }
      />

      <div className="flex-1 overflow-y-auto p-6">
        {isLoading ? (
          <div className="text-tl-muted text-sm text-center py-12">Loading…</div>
        ) : projects.length === 0 ? (
          <EmptyState
            icon={FolderOpen}
            title="No projects yet"
            description="Create your first assessment project to start scanning."
            action={
              <Link
                to="/projects/new"
                className="flex items-center gap-1.5 px-4 py-2 rounded-md bg-tl-blue text-white text-sm font-medium hover:bg-tl-blue2 transition-colors"
              >
                <Plus size={14} />
                New Assessment
              </Link>
            }
          />
        ) : (
          <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-4">
            {projects.map((p) => (
              <Link
                key={p.id}
                to={`/projects/${p.id}`}
                className="block bg-tl-surface border border-tl-border rounded-lg p-4 hover:border-tl-border2 hover:bg-tl-surface2 transition-colors group"
              >
                <div className="flex items-start justify-between mb-3">
                  <div className="flex items-center gap-2">
                    <FolderOpen size={14} className="text-tl-blue opacity-70 flex-shrink-0" />
                    <span className="text-sm font-medium text-tl-text2 group-hover:text-tl-text line-clamp-1">
                      {p.name}
                    </span>
                  </div>
                  <ArrowRight size={13} className="text-tl-muted opacity-0 group-hover:opacity-100 transition-opacity flex-shrink-0" />
                </div>

                {p.description && (
                  <p className="text-xs text-tl-muted mb-3 line-clamp-2">{p.description}</p>
                )}

                <div className="flex items-center gap-2 flex-wrap">
                  {p.critical_count > 0 && (
                    <SeverityBadge severity="CRITICAL" />
                  )}
                  {p.high_count > 0 && (
                    <SeverityBadge severity="HIGH" />
                  )}
                  <span className="text-xs text-tl-muted">
                    {p.total_findings} finding{p.total_findings !== 1 ? 's' : ''}
                  </span>
                </div>

                {p.last_scan_at && (
                  <div className="mt-2 text-[11px] text-tl-muted">
                    Last scan {formatRelative(p.last_scan_at)}
                  </div>
                )}
              </Link>
            ))}
          </div>
        )}
      </div>
    </div>
  )
}
