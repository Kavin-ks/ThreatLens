import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { Cpu, CheckCircle2, Circle, Plus, Trash2, ShieldCheck } from 'lucide-react'
import { TopBar } from '../components/layout/TopBar'
import { EmptyState } from '../components/common/EmptyState'
import { scannersApi, scannerConfigApi, projectsApi } from '../api/endpoints'
import { cn } from '../lib/utils'
import type { ScannerInfo } from '../types'

function ScannerCard({
  scanner,
  enabled,
  onToggle,
}: {
  scanner: ScannerInfo
  enabled: boolean
  onToggle: () => void
}) {
  return (
    <div
      className={cn(
        'flex items-start gap-3 p-4 rounded-lg border transition-colors',
        enabled
          ? 'bg-tl-surface border-tl-blue border-opacity-40'
          : 'bg-tl-surface border-tl-border opacity-60'
      )}
    >
      <button
        onClick={onToggle}
        className="mt-0.5 flex-shrink-0 text-tl-muted hover:text-tl-blue transition-colors"
        aria-label={enabled ? 'Disable scanner' : 'Enable scanner'}
      >
        {enabled ? (
          <CheckCircle2 size={16} className="text-emerald-400" />
        ) : (
          <Circle size={16} />
        )}
      </button>
      <div className="flex-1 min-w-0">
        <div className="flex items-center gap-2">
          <span className="text-sm font-medium text-tl-text">{scanner.name}</span>
          <span className="text-xs font-mono text-tl-muted bg-tl-surface2 px-1.5 py-0.5 rounded">
            {scanner.scanner_id}
          </span>
        </div>
        <p className="text-xs text-tl-muted mt-0.5">{scanner.description}</p>
        <div className="flex flex-wrap gap-1 mt-1.5">
          {scanner.cwe_ids.slice(0, 4).map((cwe) => (
            <span key={cwe} className="text-xs font-mono text-tl-muted bg-tl-surface2 px-1 py-0.5 rounded">
              {cwe}
            </span>
          ))}
          {scanner.requires_running_app && (
            <span className="text-xs text-amber-400 bg-amber-400 bg-opacity-10 px-1.5 py-0.5 rounded">
              dynamic
            </span>
          )}
        </div>
      </div>
    </div>
  )
}

export default function Scanners() {
  const qc = useQueryClient()
  const [selectedProjectId, setSelectedProjectId] = useState('')
  const [newTarget, setNewTarget] = useState('')

  const { data: scanners = [] } = useQuery({
    queryKey: ['scanners'],
    queryFn: scannersApi.list,
  })

  const { data: projects = [] } = useQuery({
    queryKey: ['projects'],
    queryFn: projectsApi.list,
  })

  const { data: config, isLoading: configLoading } = useQuery({
    queryKey: ['scanner-config', selectedProjectId],
    queryFn: () => scannerConfigApi.get(selectedProjectId),
    enabled: !!selectedProjectId,
  })

  const updateMutation = useMutation({
    mutationFn: (data: { enabled_scanners?: string[] | null; authorized_targets?: string[] }) =>
      scannerConfigApi.update(selectedProjectId, data),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['scanner-config', selectedProjectId] }),
  })

  const effectiveEnabled: Set<string> | null =
    config?.enabled_scanners == null ? null : new Set(config.enabled_scanners)

  const toggleScanner = (scannerId: string) => {
    if (!selectedProjectId) return
    let updated: string[]
    if (effectiveEnabled === null) {
      // All enabled → disable everything except this one would be wrong; instead
      // start explicit list with all scanners minus this one
      updated = scanners.filter((s) => s.scanner_id !== scannerId).map((s) => s.scanner_id)
    } else if (effectiveEnabled.has(scannerId)) {
      updated = [...effectiveEnabled].filter((id) => id !== scannerId)
    } else {
      updated = [...effectiveEnabled, scannerId]
    }
    updateMutation.mutate({ enabled_scanners: updated })
  }

  const addTarget = () => {
    if (!newTarget.trim() || !selectedProjectId) return
    const current = config?.authorized_targets ?? []
    if (current.includes(newTarget.trim())) return
    updateMutation.mutate({ authorized_targets: [...current, newTarget.trim()] })
    setNewTarget('')
  }

  const removeTarget = (target: string) => {
    const current = config?.authorized_targets ?? []
    updateMutation.mutate({ authorized_targets: current.filter((t) => t !== target) })
  }

  const enableAll = () => {
    updateMutation.mutate({ enabled_scanners: null as unknown as string[] })
  }

  return (
    <div className="flex flex-col h-full">
      <TopBar title="Scanners" subtitle="Enable/disable scanners and configure authorized targets" />

      <div className="flex-1 overflow-y-auto p-6 space-y-6">
        {/* Project selector */}
        <div>
          <label className="block text-xs font-medium text-tl-muted uppercase tracking-wide mb-1.5">
            Configure for project
          </label>
          <select
            value={selectedProjectId}
            onChange={(e) => setSelectedProjectId(e.target.value)}
            className="text-sm bg-tl-surface border border-tl-border rounded-md px-3 py-2 text-tl-text focus:outline-none focus:ring-1 focus:ring-tl-blue w-full max-w-sm"
          >
            <option value="">Select a project…</option>
            {projects.map((p) => (
              <option key={p.id} value={p.id}>{p.name}</option>
            ))}
          </select>
        </div>

        {!selectedProjectId ? (
          <EmptyState
            icon={Cpu}
            title="Select a project to configure scanners"
            description="Choose a project above to see and configure which scanners are enabled for it."
          />
        ) : configLoading ? (
          <div className="text-sm text-tl-muted">Loading scanner config…</div>
        ) : (
          <>
            {/* Scanners */}
            <div>
              <div className="flex items-center justify-between mb-3">
                <h2 className="text-sm font-semibold text-tl-text">
                  Scanners
                  {config && config.enabled_scanners !== null && (
                    <span className="ml-2 text-xs font-normal text-tl-muted">
                      {config.enabled_scanners.length}/{scanners.length} enabled
                    </span>
                  )}
                </h2>
                {config?.enabled_scanners !== null && (
                  <button
                    onClick={enableAll}
                    className="text-xs text-tl-blue hover:underline"
                  >
                    Enable all
                  </button>
                )}
              </div>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
                {scanners.map((s) => (
                  <ScannerCard
                    key={s.scanner_id}
                    scanner={s}
                    enabled={effectiveEnabled === null || effectiveEnabled.has(s.scanner_id)}
                    onToggle={() => toggleScanner(s.scanner_id)}
                  />
                ))}
              </div>
            </div>

            {/* Authorized targets */}
            <div>
              <div className="flex items-center gap-2 mb-3">
                <ShieldCheck size={14} className="text-tl-muted" />
                <h2 className="text-sm font-semibold text-tl-text">Authorized Dynamic Targets</h2>
              </div>
              <p className="text-xs text-tl-muted mb-3">
                Only these local targets may be used for dynamic scanning. External URLs are never tested automatically.
              </p>

              <div className="space-y-1.5 mb-3">
                {(config?.authorized_targets ?? []).length === 0 ? (
                  <p className="text-xs text-tl-muted italic">No authorized targets configured.</p>
                ) : (
                  config?.authorized_targets.map((target) => (
                    <div
                      key={target}
                      className="flex items-center gap-2 bg-tl-surface border border-tl-border rounded px-3 py-1.5"
                    >
                      <span className="flex-1 text-sm font-mono text-tl-text2">{target}</span>
                      <button
                        onClick={() => removeTarget(target)}
                        className="text-tl-muted hover:text-red-400 transition-colors"
                      >
                        <Trash2 size={13} />
                      </button>
                    </div>
                  ))
                )}
              </div>

              <div className="flex gap-2">
                <input
                  type="text"
                  placeholder="http://localhost:8080"
                  value={newTarget}
                  onChange={(e) => setNewTarget(e.target.value)}
                  onKeyDown={(e) => e.key === 'Enter' && addTarget()}
                  className="flex-1 text-sm bg-tl-surface border border-tl-border rounded-md px-3 py-1.5 text-tl-text placeholder:text-tl-muted focus:outline-none focus:ring-1 focus:ring-tl-blue font-mono"
                />
                <button
                  onClick={addTarget}
                  className="flex items-center gap-1.5 px-3 py-1.5 rounded-md bg-tl-blue text-white text-xs font-medium hover:bg-tl-blue2 transition-colors"
                >
                  <Plus size={13} />
                  Add
                </button>
              </div>
            </div>
          </>
        )}
      </div>
    </div>
  )
}
