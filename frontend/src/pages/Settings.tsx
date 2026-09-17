import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import {
  Sun, Moon, Monitor, Server, ShieldCheck, Info,
  CheckCircle2, AlertCircle, Crosshair, RefreshCw,
} from 'lucide-react'
import { TopBar } from '../components/layout/TopBar'
import { useTheme } from '../context/ThemeContext'
import { healthApi } from '../api/endpoints'
import { cn } from '../lib/utils'

// ── Helpers ────────────────────────────────────────────────────────────────────

function SettingSection({ title, icon: Icon, children }: {
  title: string
  icon: React.ComponentType<{ size?: number; className?: string }>
  children: React.ReactNode
}) {
  return (
    <section className="tl-card rounded-lg overflow-hidden">
      <div className="flex items-center gap-2 px-5 py-3.5 border-b border-tl-border bg-tl-surface2/50">
        <Icon size={14} className="text-tl-muted" />
        <h2 className="text-sm font-semibold text-tl-text">{title}</h2>
      </div>
      <div className="p-5 space-y-4">{children}</div>
    </section>
  )
}

function SettingRow({ label, description, control }: {
  label: string
  description?: string
  control: React.ReactNode
}) {
  return (
    <div className="flex items-start justify-between gap-6">
      <div className="flex-1 min-w-0">
        <div className="text-sm font-medium text-tl-text2">{label}</div>
        {description && (
          <p className="text-xs text-tl-muted mt-0.5 leading-relaxed">{description}</p>
        )}
      </div>
      <div className="flex-shrink-0">{control}</div>
    </div>
  )
}

// ── Theme picker ───────────────────────────────────────────────────────────────

function ThemePicker() {
  const { theme, setTheme } = useTheme()

  const options = [
    { value: 'dark', label: 'Dark', icon: Moon },
    { value: 'light', label: 'Light', icon: Sun },
  ] as const

  return (
    <div className="flex gap-2">
      {options.map(({ value, label, icon: Icon }) => (
        <button
          key={value}
          onClick={() => setTheme(value)}
          className={cn(
            'flex items-center gap-1.5 px-3 py-1.5 rounded-md border text-xs font-medium transition-all',
            theme === value
              ? 'border-tl-blue bg-tl-blue/10 text-tl-blue'
              : 'border-tl-border bg-tl-surface2 text-tl-text3 hover:text-tl-text2 hover:border-tl-border2'
          )}
        >
          <Icon size={13} />
          {label}
        </button>
      ))}
    </div>
  )
}

// ── Backend connection status ──────────────────────────────────────────────────

function BackendStatus() {
  const { data, isLoading, isError, refetch, isFetching } = useQuery({
    queryKey: ['health'],
    queryFn: healthApi.check,
    staleTime: 10_000,
  })

  return (
    <div className="flex items-center gap-2">
      {isLoading || isFetching ? (
        <RefreshCw size={14} className="text-tl-muted animate-spin" />
      ) : isError ? (
        <AlertCircle size={14} className="text-red-400" />
      ) : (
        <CheckCircle2 size={14} className="text-emerald-400" />
      )}
      <span className={cn(
        'text-xs font-mono',
        isError ? 'text-red-400' : isLoading ? 'text-tl-muted' : 'text-emerald-400'
      )}>
        {isLoading || isFetching
          ? 'checking…'
          : isError
          ? 'unreachable'
          : `connected · ${data?.version ?? 'ok'}`}
      </span>
      <button
        onClick={() => refetch()}
        className="text-xs text-tl-muted hover:text-tl-text2 underline underline-offset-2 transition-colors"
      >
        recheck
      </button>
    </div>
  )
}

// ── Main ───────────────────────────────────────────────────────────────────────

export default function Settings() {
  const [apiUrl, setApiUrl] = useState(() => {
    try { return localStorage.getItem('tl-api-url') || 'http://localhost:8000' } catch { return 'http://localhost:8000' }
  })
  const [saved, setSaved] = useState(false)

  const saveApiUrl = () => {
    try { localStorage.setItem('tl-api-url', apiUrl) } catch {}
    setSaved(true)
    setTimeout(() => setSaved(false), 2000)
  }

  return (
    <div className="flex flex-col h-full">
      <TopBar title="Settings" subtitle="Application preferences and configuration" />

      <div className="flex-1 overflow-y-auto p-6">
        <div className="max-w-2xl space-y-5">

          {/* Appearance */}
          <SettingSection title="Appearance" icon={Monitor}>
            <SettingRow
              label="Theme"
              description="Choose between dark and light interface themes. Your preference is saved locally."
              control={<ThemePicker />}
            />
          </SettingSection>

          {/* Backend */}
          <SettingSection title="Backend Connection" icon={Server}>
            <SettingRow
              label="API URL"
              description="The ThreatLens backend endpoint. Change this if you're running the backend on a non-default port or host."
              control={
                <div className="flex items-center gap-2">
                  <input
                    type="text"
                    value={apiUrl}
                    onChange={(e) => { setApiUrl(e.target.value); setSaved(false) }}
                    onKeyDown={(e) => e.key === 'Enter' && saveApiUrl()}
                    className="tl-input w-52 font-mono text-xs"
                    placeholder="http://localhost:8000"
                    spellCheck={false}
                  />
                  <button
                    onClick={saveApiUrl}
                    className={cn(
                      'text-xs px-2.5 py-1.5 rounded-md font-medium transition-all',
                      saved
                        ? 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/30'
                        : 'tl-btn-primary'
                    )}
                  >
                    {saved ? '✓ Saved' : 'Save'}
                  </button>
                </div>
              }
            />
            <SettingRow
              label="Status"
              description="Live connection check against the backend health endpoint."
              control={<BackendStatus />}
            />
          </SettingSection>

          {/* Security */}
          <SettingSection title="Security Policy" icon={ShieldCheck}>
            <SettingRow
              label="Scan scope"
              description="ThreatLens only performs scans against explicitly authorized, local targets. Dynamic scanners will not contact any external host unless it is listed in the project's authorized targets."
              control={
                <span className="text-xs bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 px-2 py-1 rounded-md font-medium">
                  Enforced
                </span>
              }
            />
            <SettingRow
              label="AI-assisted triage"
              description="AI triage is opt-in per finding. Source code and sensitive data are never sent to an external AI service without explicit configuration."
              control={
                <span className="text-xs bg-tl-surface2 text-tl-muted border border-tl-border px-2 py-1 rounded-md font-medium font-mono">
                  opt-in
                </span>
              }
            />
          </SettingSection>

          {/* About */}
          <SettingSection title="About ThreatLens" icon={Info}>
            <div className="flex items-start gap-4">
              <div className="flex items-center justify-center w-12 h-12 rounded-xl bg-tl-blue/15 border border-tl-blue/25 flex-shrink-0">
                <Crosshair size={22} className="text-tl-blue" />
              </div>
              <div className="space-y-1 text-sm">
                <div className="flex items-center gap-2 flex-wrap">
                  <span className="font-semibold text-tl-text font-mono">ThreatLens</span>
                  <span className="text-xs bg-tl-blue/10 text-tl-blue px-1.5 py-0.5 rounded font-mono border border-tl-blue/20">
                    v1.0.0
                  </span>
                </div>
                <p className="text-xs text-tl-muted leading-relaxed">
                  Evidence-driven security assessment platform built for Smart India Hackathon 2026
                  (NTRO problem statement). Automates vulnerability detection across injection,
                  cryptography, authentication, authorization, dependency, configuration, and
                  SSRF/proxy attack surfaces.
                </p>
                <div className="flex flex-wrap gap-3 pt-1 text-xs text-tl-muted font-mono">
                  <span>FastAPI · SQLAlchemy 2.0</span>
                  <span className="text-tl-border">·</span>
                  <span>React 18 · Vite · Tailwind</span>
                  <span className="text-tl-border">·</span>
                  <span>fpdf2 · Pydantic v2</span>
                </div>
              </div>
            </div>

            <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 pt-1">
              {[
                { label: 'Phases',     value: '11 / 11' },
                { label: 'Scanners',   value: '8 categories' },
                { label: 'Tests',      value: '276 passing' },
                { label: 'Assessment', value: 'World Monitor' },
              ].map(({ label, value }) => (
                <div key={label} className="bg-tl-surface2 border border-tl-border rounded-md p-2.5 text-center">
                  <div className="text-xs font-medium text-tl-text font-mono">{value}</div>
                  <div className="text-[10px] text-tl-muted mt-0.5">{label}</div>
                </div>
              ))}
            </div>
          </SettingSection>

        </div>
      </div>
    </div>
  )
}
