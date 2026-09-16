import { useState } from 'react'
import { Link, useParams } from 'react-router-dom'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import {
  ArrowLeft,
  Loader2,
  AlertCircle,
  ShieldAlert,
  FileText,
  Code2,
  Globe,
  Settings,
  Package,
  Clock,
  ChevronRight,
  ChevronDown,
} from 'lucide-react'
import { TopBar } from '../components/layout/TopBar'
import { SeverityBadge } from '../components/common/SeverityBadge'
import { ConfidenceBadge } from '../components/common/ConfidenceBadge'
import { StatusBadge } from '../components/common/StatusBadge'
import { findingsApi } from '../api/endpoints'
import { formatDate } from '../lib/utils'
import type { Evidence, FindingHistoryEntry, FindingStatus } from '../types'

const FINDING_STATUSES: FindingStatus[] = [
  'DETECTED',
  'VALIDATING',
  'CONFIRMED',
  'REJECTED',
  'REMEDIATION',
  'RETESTING',
  'RESOLVED',
]

// ─── Evidence viewer ──────────────────────────────────────────────────────────

function EvidenceTypeIcon({ type }: { type: string }) {
  const icons: Record<string, React.ComponentType<any>> = {
    code_snippet:      Code2,
    request_response:  Globe,
    config_value:      Settings,
    dependency_record: Package,
    regex_match:       FileText,
  }
  const Icon = icons[type] ?? FileText
  return <Icon size={13} className="text-tl-muted" />
}

function parseMetadata(json: string | null): Record<string, unknown> {
  if (!json) return {}
  try { return JSON.parse(json) } catch { return {} }
}

function CodeEvidenceBlock({ evidence }: { evidence: Evidence }) {
  const meta = parseMetadata(evidence.metadata_json)
  return (
    <div className="rounded-lg overflow-hidden border border-tl-border">
      <div className="flex items-center gap-2 px-3 py-2 bg-tl-surface2 border-b border-tl-border">
        <Code2 size={12} className="text-tl-muted" />
        <span className="text-xs font-mono text-tl-muted">
          {meta.file as string ?? 'code'}
          {meta.start_line != null ? `:${meta.start_line}` : ''}
        </span>
      </div>
      <pre className="overflow-x-auto p-4 text-xs font-mono leading-relaxed text-tl-text2 bg-tl-bg">
        {evidence.content ?? '(no content)'}
      </pre>
    </div>
  )
}

function RequestResponseBlock({ evidence }: { evidence: Evidence }) {
  const lines = (evidence.content ?? '').split('\n')
  const requestLines: string[] = []
  const responseLines: string[] = []
  let inResponse = false

  for (const line of lines) {
    if (line.startsWith('HTTP Status:') || line.startsWith('Response snippet')) {
      inResponse = true
    }
    if (inResponse) {
      responseLines.push(line)
    } else {
      requestLines.push(line)
    }
  }

  return (
    <div className="space-y-2">
      {requestLines.length > 0 && (
        <div className="rounded-lg overflow-hidden border border-tl-border">
          <div className="px-3 py-1.5 bg-tl-surface2 border-b border-tl-border text-[10px] font-semibold text-tl-muted uppercase tracking-wider">
            Request / Probe
          </div>
          <pre className="p-3 text-xs font-mono text-tl-text2 bg-tl-bg overflow-x-auto">
            {requestLines.join('\n')}
          </pre>
        </div>
      )}
      {responseLines.length > 0 && (
        <div className="rounded-lg overflow-hidden border border-tl-border">
          <div className="px-3 py-1.5 bg-tl-surface2 border-b border-tl-border text-[10px] font-semibold text-tl-muted uppercase tracking-wider">
            Response
          </div>
          <pre className="p-3 text-xs font-mono text-tl-text2 bg-tl-bg overflow-x-auto">
            {responseLines.join('\n')}
          </pre>
        </div>
      )}
    </div>
  )
}

function EvidenceCard({ evidence }: { evidence: Evidence }) {
  const [expanded, setExpanded] = useState(true)
  return (
    <div className="border border-tl-border rounded-lg overflow-hidden">
      <button
        onClick={() => setExpanded((v) => !v)}
        className="w-full flex items-center gap-2 px-4 py-2.5 bg-tl-surface hover:bg-tl-surface2 transition-colors text-left"
      >
        <EvidenceTypeIcon type={evidence.evidence_type} />
        <span className="flex-1 text-xs text-tl-text2 font-medium">
          {evidence.title ?? evidence.evidence_type.replace('_', ' ')}
        </span>
        <span className="text-[10px] text-tl-muted font-mono px-1.5 py-0.5 bg-tl-surface2 rounded border border-tl-border">
          {evidence.evidence_type}
        </span>
        {expanded ? (
          <ChevronDown size={13} className="text-tl-muted" />
        ) : (
          <ChevronRight size={13} className="text-tl-muted" />
        )}
      </button>

      {expanded && evidence.content && (
        <div className="p-3 border-t border-tl-border bg-tl-bg">
          {evidence.evidence_type === 'code_snippet' || evidence.evidence_type === 'regex_match' ? (
            <CodeEvidenceBlock evidence={evidence} />
          ) : evidence.evidence_type === 'request_response' ? (
            <RequestResponseBlock evidence={evidence} />
          ) : (
            <pre className="text-xs font-mono text-tl-text2 whitespace-pre-wrap overflow-x-auto">
              {evidence.content}
            </pre>
          )}
          {evidence.description && (
            <p className="mt-2 text-xs text-tl-muted">{evidence.description}</p>
          )}
        </div>
      )}
    </div>
  )
}

// ─── History timeline ─────────────────────────────────────────────────────────

function HistoryTimeline({ history }: { history: FindingHistoryEntry[] }) {
  const sorted = [...history].sort((a, b) => new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime())
  return (
    <div className="space-y-3">
      {sorted.map((entry, i) => (
        <div key={entry.id} className="flex gap-3">
          <div className="flex flex-col items-center">
            <div className="w-2 h-2 rounded-full bg-tl-blue mt-1.5 flex-shrink-0" />
            {i < sorted.length - 1 && (
              <div className="w-px flex-1 bg-tl-border mt-1" />
            )}
          </div>
          <div className="flex-1 pb-3">
            <div className="flex items-center gap-2 flex-wrap">
              {entry.from_status && (
                <>
                  <span className="text-xs text-tl-muted">{entry.from_status}</span>
                  <ChevronRight size={11} className="text-tl-muted" />
                </>
              )}
              <span className="text-xs font-medium text-tl-text2">{entry.to_status}</span>
              <span className="text-xs text-tl-muted">by {entry.changed_by}</span>
            </div>
            {entry.note && (
              <p className="text-xs text-tl-muted mt-0.5 italic">"{entry.note}"</p>
            )}
            <div className="text-[10px] text-tl-muted mt-0.5">{formatDate(entry.timestamp)}</div>
          </div>
        </div>
      ))}
    </div>
  )
}

// ─── Main component ───────────────────────────────────────────────────────────

export default function FindingDetail() {
  const { id: projectId, findingId } = useParams<{ id: string; findingId: string }>()
  const queryClient = useQueryClient()
  const [statusNote, setStatusNote] = useState('')
  const [showStatusMenu, setShowStatusMenu] = useState(false)

  const { data: finding, isLoading, isError } = useQuery({
    queryKey: ['finding', projectId, findingId],
    queryFn: () => findingsApi.get(projectId!, findingId!),
    enabled: !!(projectId && findingId),
  })

  const statusMutation = useMutation({
    mutationFn: ({ status, note }: { status: string; note?: string }) =>
      findingsApi.updateStatus(projectId!, findingId!, status, note),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['finding', projectId, findingId] })
      queryClient.invalidateQueries({ queryKey: ['findings', projectId] })
      setShowStatusMenu(false)
      setStatusNote('')
    },
  })

  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-full">
        <Loader2 size={20} className="animate-spin text-tl-muted" />
      </div>
    )
  }

  if (isError || !finding) {
    return (
      <div className="flex flex-col items-center justify-center h-full gap-3">
        <AlertCircle size={24} className="text-red-400" />
        <p className="text-sm text-tl-muted">Finding not found.</p>
        <Link to={`/projects/${projectId}`} className="text-xs text-tl-blue hover:underline">
          Back to project
        </Link>
      </div>
    )
  }

  return (
    <div className="flex flex-col h-full">
      <TopBar
        title={finding.title}
        subtitle={`${finding.scanner_id} · ${finding.category}`}
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

      <div className="flex-1 overflow-y-auto p-6">
        <div className="max-w-3xl space-y-6">
          {/* Header badges */}
          <div className="flex flex-wrap items-center gap-2">
            <SeverityBadge severity={finding.severity} size="md" />
            <ConfidenceBadge confidence={finding.confidence} size="md" />
            <StatusBadge status={finding.status} />
            {finding.cwe_id && (
              <span className="text-xs font-mono text-tl-muted px-2 py-0.5 bg-tl-surface border border-tl-border rounded">
                {finding.cwe_id}
              </span>
            )}
            {finding.owasp_category && (
              <span className="text-xs text-tl-muted px-2 py-0.5 bg-tl-surface border border-tl-border rounded">
                {finding.owasp_category}
              </span>
            )}
          </div>

          {/* Location */}
          {(finding.affected_endpoint || finding.affected_file || finding.affected_component) && (
            <div className="flex items-center gap-2 text-xs">
              <span className="text-tl-muted">Location:</span>
              <span className="font-mono text-tl-text2 bg-tl-surface border border-tl-border rounded px-2 py-0.5">
                {finding.affected_endpoint
                  ?? (finding.affected_file
                    ? `${finding.affected_file}${finding.affected_line ? `:${finding.affected_line}` : ''}`
                    : finding.affected_component)}
              </span>
            </div>
          )}

          {/* Description */}
          <Section title="Description">
            <p className="text-sm text-tl-text2 leading-relaxed">{finding.description}</p>
          </Section>

          {/* Impact */}
          {finding.impact && (
            <Section title="Impact">
              <p className="text-sm text-tl-text2 leading-relaxed">{finding.impact}</p>
            </Section>
          )}

          {/* Remediation */}
          {finding.remediation && (
            <Section title="Remediation">
              <p className="text-sm text-tl-text2 leading-relaxed">{finding.remediation}</p>
            </Section>
          )}

          {/* Evidence */}
          {finding.evidence.length > 0 && (
            <Section title={`Evidence (${finding.evidence.length})`}>
              <div className="space-y-3">
                {finding.evidence.map((ev) => (
                  <EvidenceCard key={ev.id} evidence={ev} />
                ))}
              </div>
            </Section>
          )}

          {/* Status lifecycle */}
          <Section title="Lifecycle">
            <div className="space-y-4">
              <div className="flex flex-wrap items-center gap-2">
                <span className="text-xs text-tl-muted">Current status:</span>
                <StatusBadge status={finding.status} />
                <button
                  onClick={() => setShowStatusMenu((v) => !v)}
                  className="text-xs text-tl-blue hover:underline"
                >
                  {showStatusMenu ? 'Cancel' : 'Change'}
                </button>
              </div>

              {showStatusMenu && (
                <div className="bg-tl-surface border border-tl-border rounded-lg p-4 space-y-3">
                  <div className="flex flex-wrap gap-2">
                    {FINDING_STATUSES.filter((s) => s !== finding.status).map((s) => (
                      <button
                        key={s}
                        onClick={() =>
                          statusMutation.mutate({ status: s, note: statusNote || undefined })
                        }
                        disabled={statusMutation.isPending}
                        className="px-3 py-1.5 rounded-md bg-tl-surface2 hover:bg-tl-surface3 border border-tl-border text-xs text-tl-text2 transition-colors disabled:opacity-50"
                      >
                        → {s}
                      </button>
                    ))}
                  </div>
                  <input
                    type="text"
                    value={statusNote}
                    onChange={(e) => setStatusNote(e.target.value)}
                    placeholder="Add a note (optional)…"
                    className="w-full bg-tl-bg border border-tl-border rounded-md px-3 py-2 text-xs text-tl-text placeholder:text-tl-muted focus:outline-none focus:border-tl-blue"
                  />
                </div>
              )}

              {finding.history.length > 0 && (
                <HistoryTimeline history={finding.history} />
              )}
            </div>
          </Section>

          {/* Metadata footer */}
          <div className="text-[11px] text-tl-muted space-y-0.5 pt-2 border-t border-tl-border">
            <div>Scanner: <span className="font-mono">{finding.scanner_id}</span></div>
            <div>First detected: {formatDate(finding.created_at)}</div>
            <div>Scan run: <span className="font-mono">{finding.scan_run_id.slice(0, 12)}…</span></div>
            {finding.fingerprint && (
              <div>Fingerprint: <span className="font-mono">{(finding as any).fingerprint}</span></div>
            )}
          </div>
        </div>
      </div>
    </div>
  )
}

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div>
      <h3 className="text-xs font-semibold text-tl-muted uppercase tracking-wider mb-2">{title}</h3>
      {children}
    </div>
  )
}
