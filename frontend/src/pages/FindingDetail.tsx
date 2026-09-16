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
  CheckCircle2,
  XCircle,
  RefreshCw,
  PlusCircle,
  RotateCcw,
} from 'lucide-react'
import { TopBar } from '../components/layout/TopBar'
import { SeverityBadge } from '../components/common/SeverityBadge'
import { ConfidenceBadge } from '../components/common/ConfidenceBadge'
import { StatusBadge } from '../components/common/StatusBadge'
import { findingsApi } from '../api/endpoints'
import { formatDate, formatRelative } from '../lib/utils'
import type { Evidence, FindingHistoryEntry, FindingStatus, Confidence, RemediationRecord } from '../types'

const FINDING_STATUSES: FindingStatus[] = [
  'DETECTED', 'VALIDATING', 'CONFIRMED', 'REJECTED', 'REMEDIATION', 'RETESTING', 'RESOLVED',
]
const CONFIDENCE_LEVELS: Confidence[] = ['CONFIRMED', 'LIKELY', 'POSSIBLE', 'FALSE_POSITIVE']

const RETEST_STATUS_CONFIG: Record<string, { label: string; cls: string; icon: React.ComponentType<any> }> = {
  pending:      { label: 'Pending',      cls: 'text-tl-muted',    icon: Clock },
  passed:       { label: 'Passed',       cls: 'text-emerald-400', icon: CheckCircle2 },
  failed:       { label: 'Failed',       cls: 'text-red-400',     icon: XCircle },
  inconclusive: { label: 'Inconclusive', cls: 'text-yellow-400',  icon: AlertCircle },
}

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
        {expanded ? <ChevronDown size={13} className="text-tl-muted" /> : <ChevronRight size={13} className="text-tl-muted" />}
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
  const sorted = [...history].sort(
    (a, b) => new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime()
  )
  return (
    <div className="space-y-3">
      {sorted.map((entry, i) => (
        <div key={entry.id} className="flex gap-3">
          <div className="flex flex-col items-center">
            <div className="w-2 h-2 rounded-full bg-tl-blue mt-1.5 flex-shrink-0" />
            {i < sorted.length - 1 && <div className="w-px flex-1 bg-tl-border mt-1" />}
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
            {entry.note && <p className="text-xs text-tl-muted mt-0.5 italic">"{entry.note}"</p>}
            <div className="text-[10px] text-tl-muted mt-0.5">{formatDate(entry.timestamp)}</div>
          </div>
        </div>
      ))}
    </div>
  )
}

// ─── Remediation record card ──────────────────────────────────────────────────

function RemediationCard({
  record,
  projectId,
  findingId,
  onRetestDone,
}: {
  record: RemediationRecord
  projectId: string
  findingId: string
  onRetestDone: () => void
}) {
  const [retesting, setRetesting] = useState(false)
  const [retestNote, setRetestNote] = useState('')
  const queryClient = useQueryClient()

  const retestMutation = useMutation({
    mutationFn: () => findingsApi.retest(projectId, findingId, record.id, retestNote || undefined),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['finding', projectId, findingId] })
      queryClient.invalidateQueries({ queryKey: ['findings', projectId] })
      setRetesting(false)
      setRetestNote('')
      onRetestDone()
    },
  })

  const cfg = RETEST_STATUS_CONFIG[record.retest_status] ?? RETEST_STATUS_CONFIG.pending
  const Icon = cfg.icon

  return (
    <div className="border border-tl-border rounded-lg p-4 space-y-3">
      <div className="flex items-start justify-between gap-2">
        <p className="text-xs text-tl-text2 flex-1">{record.description}</p>
        <div className={`flex items-center gap-1 text-xs font-medium ${cfg.cls} flex-shrink-0`}>
          <Icon size={12} />
          <span>{cfg.label}</span>
        </div>
      </div>

      {record.applied_by && (
        <div className="text-[10px] text-tl-muted">Applied by: {record.applied_by}</div>
      )}

      {record.patch_diff && (
        <pre className="text-[10px] font-mono text-tl-text2 bg-tl-bg border border-tl-border rounded p-2 overflow-x-auto max-h-24">
          {record.patch_diff}
        </pre>
      )}

      {record.retest_notes && (
        <div className="text-xs text-tl-muted italic">{record.retest_notes}</div>
      )}

      {record.retest_at && (
        <div className="text-[10px] text-tl-muted">Retested: {formatRelative(record.retest_at)}</div>
      )}

      {/* Retest controls */}
      {record.retest_status !== 'passed' && (
        <div>
          <button
            onClick={() => setRetesting((v) => !v)}
            className="flex items-center gap-1.5 text-xs text-tl-blue hover:underline"
          >
            <RotateCcw size={11} />
            {retesting ? 'Cancel' : 'Run Retest'}
          </button>

          {retesting && (
            <div className="mt-2 space-y-2">
              <input
                type="text"
                value={retestNote}
                onChange={(e) => setRetestNote(e.target.value)}
                placeholder="Optional note..."
                className="w-full bg-tl-bg border border-tl-border rounded px-2 py-1.5 text-xs text-tl-text placeholder:text-tl-muted focus:outline-none focus:border-tl-blue"
              />
              <button
                onClick={() => retestMutation.mutate()}
                disabled={retestMutation.isPending}
                className="flex items-center gap-1.5 px-3 py-1.5 rounded bg-tl-blue text-white text-xs font-medium hover:bg-blue-500 transition-colors disabled:opacity-50"
              >
                {retestMutation.isPending ? <Loader2 size={11} className="animate-spin" /> : <RefreshCw size={11} />}
                Run Retest Now
              </button>
            </div>
          )}
        </div>
      )}
    </div>
  )
}

// ─── Main component ───────────────────────────────────────────────────────────

export default function FindingDetail() {
  const { id: projectId, findingId } = useParams<{ id: string; findingId: string }>()
  const queryClient = useQueryClient()

  const [statusNote, setStatusNote] = useState('')
  const [showStatusMenu, setShowStatusMenu] = useState(false)
  const [showValidateMenu, setShowValidateMenu] = useState(false)
  const [validateNote, setValidateNote] = useState('')
  const [showAddRemediation, setShowAddRemediation] = useState(false)
  const [remDesc, setRemDesc] = useState('')
  const [remAppliedBy, setRemAppliedBy] = useState('')
  const [remPatchDiff, setRemPatchDiff] = useState('')

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

  const validateMutation = useMutation({
    mutationFn: ({ confidence, note }: { confidence: string; note?: string }) =>
      findingsApi.validate(projectId!, findingId!, confidence, note),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['finding', projectId, findingId] })
      queryClient.invalidateQueries({ queryKey: ['findings', projectId] })
      setShowValidateMenu(false)
      setValidateNote('')
    },
  })

  const remediationMutation = useMutation({
    mutationFn: () =>
      findingsApi.createRemediation(projectId!, findingId!, {
        description: remDesc,
        applied_by: remAppliedBy || undefined,
        patch_diff: remPatchDiff || undefined,
      }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['finding', projectId, findingId] })
      queryClient.invalidateQueries({ queryKey: ['findings', projectId] })
      setShowAddRemediation(false)
      setRemDesc('')
      setRemAppliedBy('')
      setRemPatchDiff('')
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

          {/* Remediation guidance */}
          {finding.remediation && (
            <Section title="Remediation Guidance">
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

          {/* Validation */}
          <Section title="Validation">
            <div className="space-y-3">
              <div className="flex items-center gap-3">
                <span className="text-xs text-tl-muted">Current confidence:</span>
                <ConfidenceBadge confidence={finding.confidence} size="md" />
                <button
                  onClick={() => setShowValidateMenu((v) => !v)}
                  className="text-xs text-tl-blue hover:underline"
                >
                  {showValidateMenu ? 'Cancel' : 'Validate'}
                </button>
              </div>

              {showValidateMenu && (
                <div className="bg-tl-surface border border-tl-border rounded-lg p-4 space-y-3">
                  <p className="text-xs text-tl-muted">Set confidence level based on your validation:</p>
                  <div className="flex flex-wrap gap-2">
                    {CONFIDENCE_LEVELS.map((c) => (
                      <button
                        key={c}
                        onClick={() => validateMutation.mutate({ confidence: c, note: validateNote || undefined })}
                        disabled={validateMutation.isPending}
                        className="px-3 py-1.5 rounded-md bg-tl-surface2 hover:bg-tl-surface3 border border-tl-border text-xs text-tl-text2 transition-colors disabled:opacity-50"
                      >
                        {c === 'FALSE_POSITIVE' ? 'False Positive' : c}
                      </button>
                    ))}
                  </div>
                  <input
                    type="text"
                    value={validateNote}
                    onChange={(e) => setValidateNote(e.target.value)}
                    placeholder="Validation note (optional)..."
                    className="w-full bg-tl-bg border border-tl-border rounded-md px-3 py-2 text-xs text-tl-text placeholder:text-tl-muted focus:outline-none focus:border-tl-blue"
                  />
                </div>
              )}
            </div>
          </Section>

          {/* Remediation records */}
          <Section title="Remediation Records">
            <div className="space-y-3">
              {(finding.remediation_records ?? []).map((rec) => (
                <RemediationCard
                  key={rec.id}
                  record={rec}
                  projectId={projectId!}
                  findingId={findingId!}
                  onRetestDone={() => {
                    queryClient.invalidateQueries({ queryKey: ['finding', projectId, findingId] })
                  }}
                />
              ))}

              {/* Add remediation */}
              {!showAddRemediation ? (
                <button
                  onClick={() => setShowAddRemediation(true)}
                  className="flex items-center gap-1.5 text-xs text-tl-blue hover:underline"
                >
                  <PlusCircle size={12} />
                  Record Remediation
                </button>
              ) : (
                <div className="border border-tl-border rounded-lg p-4 space-y-3">
                  <p className="text-xs font-medium text-tl-text2">Record a remediation</p>
                  <textarea
                    value={remDesc}
                    onChange={(e) => setRemDesc(e.target.value)}
                    placeholder="Describe what was fixed..."
                    rows={3}
                    className="w-full bg-tl-bg border border-tl-border rounded-md px-3 py-2 text-xs text-tl-text placeholder:text-tl-muted focus:outline-none focus:border-tl-blue resize-none"
                  />
                  <input
                    type="text"
                    value={remAppliedBy}
                    onChange={(e) => setRemAppliedBy(e.target.value)}
                    placeholder="Applied by (optional)..."
                    className="w-full bg-tl-bg border border-tl-border rounded-md px-3 py-2 text-xs text-tl-text placeholder:text-tl-muted focus:outline-none focus:border-tl-blue"
                  />
                  <textarea
                    value={remPatchDiff}
                    onChange={(e) => setRemPatchDiff(e.target.value)}
                    placeholder="Patch diff or code change (optional)..."
                    rows={4}
                    className="w-full bg-tl-bg border border-tl-border rounded-md px-3 py-2 text-xs font-mono text-tl-text placeholder:text-tl-muted focus:outline-none focus:border-tl-blue resize-none"
                  />
                  <div className="flex gap-2">
                    <button
                      onClick={() => remediationMutation.mutate()}
                      disabled={!remDesc.trim() || remediationMutation.isPending}
                      className="flex items-center gap-1.5 px-3 py-1.5 rounded bg-tl-blue text-white text-xs font-medium hover:bg-blue-500 transition-colors disabled:opacity-50"
                    >
                      {remediationMutation.isPending ? <Loader2 size={11} className="animate-spin" /> : null}
                      Save
                    </button>
                    <button
                      onClick={() => setShowAddRemediation(false)}
                      className="px-3 py-1.5 rounded text-xs text-tl-muted hover:text-tl-text2 transition-colors"
                    >
                      Cancel
                    </button>
                  </div>
                </div>
              )}
            </div>
          </Section>

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
                        onClick={() => statusMutation.mutate({ status: s, note: statusNote || undefined })}
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
                    placeholder="Add a note (optional)..."
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
            <div>Scan run: <span className="font-mono">{finding.scan_run_id.slice(0, 12)}...</span></div>
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
