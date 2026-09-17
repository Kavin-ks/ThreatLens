import { useState } from 'react'
import { Link } from 'react-router-dom'
import {
  BookOpen, Crosshair, FolderOpen, Scan, ShieldAlert,
  FileText, Cpu, ChevronDown, ChevronRight, ExternalLink,
  CheckCircle2, AlertTriangle, Clock, RefreshCw, XCircle,
  Wrench, Plus, Activity,
} from 'lucide-react'
import { TopBar } from '../components/layout/TopBar'
import { cn } from '../lib/utils'

// ── Accordion ─────────────────────────────────────────────────────────────────

function Accordion({ title, children, defaultOpen = false }: {
  title: string
  children: React.ReactNode
  defaultOpen?: boolean
}) {
  const [open, setOpen] = useState(defaultOpen)
  return (
    <div className="border border-tl-border rounded-lg overflow-hidden">
      <button
        onClick={() => setOpen(!open)}
        className="w-full flex items-center justify-between px-4 py-3 bg-tl-surface hover:bg-tl-surface2 transition-colors text-left"
      >
        <span className="text-sm font-medium text-tl-text">{title}</span>
        {open ? <ChevronDown size={15} className="text-tl-muted flex-shrink-0" /> : <ChevronRight size={15} className="text-tl-muted flex-shrink-0" />}
      </button>
      {open && (
        <div className="px-4 pb-4 pt-2 bg-tl-surface border-t border-tl-border text-sm text-tl-text2 space-y-2 animate-fade-in">
          {children}
        </div>
      )}
    </div>
  )
}

// ── Step ──────────────────────────────────────────────────────────────────────

function Step({ n, title, children }: { n: number; title: string; children: React.ReactNode }) {
  return (
    <div className="flex gap-4">
      <div className="flex-shrink-0 flex items-center justify-center w-7 h-7 rounded-full bg-tl-blue/15 border border-tl-blue/30 text-tl-blue text-xs font-bold font-mono mt-0.5">
        {n}
      </div>
      <div>
        <div className="text-sm font-medium text-tl-text mb-1">{title}</div>
        <div className="text-sm text-tl-text3 leading-relaxed">{children}</div>
      </div>
    </div>
  )
}

// ── Status pill ───────────────────────────────────────────────────────────────

function StatusPill({ label, color }: { label: string; color: string }) {
  return (
    <span className={cn('inline-flex items-center px-2 py-0.5 rounded text-xs font-medium border', color)}>
      {label}
    </span>
  )
}

// ── Shortcut row ──────────────────────────────────────────────────────────────

function Shortcut({ keys, desc }: { keys: string[]; desc: string }) {
  return (
    <div className="flex items-center justify-between py-1.5 border-b border-tl-border last:border-0">
      <span className="text-sm text-tl-text2">{desc}</span>
      <div className="flex items-center gap-1">
        {keys.map((k, i) => (
          <span key={i} className="px-1.5 py-0.5 bg-tl-surface2 border border-tl-border rounded text-xs font-mono text-tl-text3">
            {k}
          </span>
        ))}
      </div>
    </div>
  )
}

// ── Scanner reference row ─────────────────────────────────────────────────────

function ScannerRow({ id, name, desc, cwes }: { id: string; name: string; desc: string; cwes: string[] }) {
  return (
    <div className="flex items-start gap-3 py-2.5 border-b border-tl-border last:border-0">
      <code className="text-xs font-mono bg-tl-surface2 border border-tl-border px-1.5 py-0.5 rounded text-tl-muted flex-shrink-0 mt-0.5">
        {id}
      </code>
      <div className="flex-1 min-w-0">
        <div className="text-sm font-medium text-tl-text2">{name}</div>
        <div className="text-xs text-tl-muted mt-0.5">{desc}</div>
      </div>
      <div className="flex gap-1 flex-shrink-0 flex-wrap justify-end">
        {cwes.map((c) => (
          <span key={c} className="text-[10px] font-mono text-tl-muted bg-tl-surface2 px-1 rounded">{c}</span>
        ))}
      </div>
    </div>
  )
}

// ── Page ──────────────────────────────────────────────────────────────────────

const sections = [
  { id: 'getting-started', label: 'Getting Started', icon: BookOpen },
  { id: 'workflow',        label: 'Assessment Workflow', icon: Activity },
  { id: 'findings',        label: 'Understanding Findings', icon: ShieldAlert },
  { id: 'lifecycle',       label: 'Finding Lifecycle', icon: RefreshCw },
  { id: 'scanners',        label: 'Scanner Reference', icon: Cpu },
  { id: 'reports',         label: 'Reports', icon: FileText },
  { id: 'shortcuts',       label: 'Keyboard Shortcuts', icon: Crosshair },
]

export default function Help() {
  const [activeSection, setActiveSection] = useState('getting-started')

  return (
    <div className="flex flex-col h-full">
      <TopBar title="Help & Guide" subtitle="How to use ThreatLens effectively" />

      <div className="flex flex-1 overflow-hidden">
        {/* TOC sidebar */}
        <nav className="w-52 flex-shrink-0 border-r border-tl-border overflow-y-auto py-4 bg-tl-surface hidden md:block">
          <div className="px-3 mb-2">
            <span className="section-header">Contents</span>
          </div>
          {sections.map(({ id, label, icon: Icon }) => (
            <button
              key={id}
              onClick={() => {
                setActiveSection(id)
                document.getElementById(id)?.scrollIntoView({ behavior: 'smooth' })
              }}
              className={cn(
                'w-full flex items-center gap-2 px-3 py-2 text-xs transition-colors text-left',
                activeSection === id
                  ? 'text-tl-blue bg-tl-blue/10'
                  : 'text-tl-text3 hover:text-tl-text2 hover:bg-tl-surface2'
              )}
            >
              <Icon size={13} className="flex-shrink-0" />
              {label}
            </button>
          ))}
        </nav>

        {/* Content */}
        <div className="flex-1 overflow-y-auto">
          <div className="max-w-2xl mx-auto px-6 py-6 space-y-10">

            {/* ── Getting Started ── */}
            <section id="getting-started" className="scroll-mt-4">
              <div className="flex items-center gap-2 mb-4">
                <BookOpen size={16} className="text-tl-blue" />
                <h2 className="text-base font-semibold text-tl-text">Getting Started</h2>
              </div>

              <p className="text-sm text-tl-text3 leading-relaxed mb-4">
                ThreatLens is an evidence-driven security assessment platform. It automates
                vulnerability scanning, organises findings through a structured lifecycle, and
                generates audit-ready PDF reports. Everything you do here is against
                <strong className="text-tl-text2"> authorized, local targets only</strong>.
              </p>

              <div className="space-y-4">
                <Step n={1} title="Start the backend">
                  From the project root, activate the virtualenv and run the FastAPI server:
                  <pre className="code-block mt-2 text-xs">
{`cd backend
source .venv/bin/activate
uvicorn app.main:app --reload`}
                  </pre>
                  The API and interactive docs will be at{' '}
                  <code className="text-tl-blue text-xs">http://localhost:8000/docs</code>.
                </Step>

                <Step n={2} title="Open the frontend">
                  In a second terminal:
                  <pre className="code-block mt-2 text-xs">
{`cd frontend
npm install   # first time only
npm run dev`}
                  </pre>
                  Navigate to <code className="text-tl-blue text-xs">http://localhost:5173</code>.
                </Step>

                <Step n={3} title="Create your first project">
                  Click <strong className="text-tl-text2">New Assessment</strong> on the Dashboard
                  or go to{' '}
                  <Link to="/projects/new" className="text-tl-blue hover:underline">
                    Projects → New
                  </Link>
                  . Give it a name and point{' '}
                  <code className="text-xs text-tl-blue">target_path</code> at the local source
                  directory you want assessed.
                </Step>

                <Step n={4} title="Run a scan">
                  Open the project, click <strong className="text-tl-text2">Run Scan</strong>.
                  ThreatLens autodiscovers all registered scanners and runs them against the target.
                  Results appear under the project's Findings tab as they land.
                </Step>

                <Step n={5} title="Review and resolve">
                  Each finding has evidence attached. Validate it, record a remediation, retest,
                  and mark it RESOLVED. Then generate a PDF report.
                </Step>
              </div>
            </section>

            {/* ── Assessment Workflow ── */}
            <section id="workflow" className="scroll-mt-4">
              <div className="flex items-center gap-2 mb-4">
                <Activity size={16} className="text-tl-blue" />
                <h2 className="text-base font-semibold text-tl-text">Assessment Workflow</h2>
              </div>

              <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 mb-4">
                {[
                  { icon: Plus,       title: 'Create Project',  desc: 'Set target path, description, and authorized scan targets.' },
                  { icon: Scan,       title: 'Scan',            desc: 'Scanners run in parallel; each attaches evidence to findings.' },
                  { icon: ShieldAlert,title: 'Triage Findings', desc: 'Validate confidence, update CVSS, reject false positives.' },
                  { icon: Wrench,     title: 'Remediate',       desc: 'Record the fix with a patch diff and assessor notes.' },
                  { icon: RefreshCw,  title: 'Retest',          desc: 'Re-run the scanner or manually verify the fix.' },
                  { icon: FileText,   title: 'Report',          desc: 'Generate a PDF with all evidence and lifecycle history.' },
                ].map(({ icon: Icon, title, desc }) => (
                  <div key={title} className="tl-card rounded-lg p-3">
                    <div className="flex items-center gap-2 mb-1.5">
                      <Icon size={13} className="text-tl-blue" />
                      <span className="text-xs font-medium text-tl-text">{title}</span>
                    </div>
                    <p className="text-xs text-tl-muted leading-relaxed">{desc}</p>
                  </div>
                ))}
              </div>

              <Accordion title="What happens during a scan?" defaultOpen>
                <ol className="list-decimal list-inside space-y-1 text-tl-text3 text-sm">
                  <li>The stack detector inspects the target to identify framework and language.</li>
                  <li>The scanner orchestrator selects scanners whose <code className="text-xs text-tl-blue">can_scan()</code> returns true.</li>
                  <li>Each scanner runs independently, producing <code className="text-xs text-tl-blue">RawFinding</code> objects.</li>
                  <li>Findings are fingerprinted — duplicates from multiple scanners are deduplicated.</li>
                  <li>Evidence (file path, line, code snippet, tool output) is attached to each finding.</li>
                  <li>The scan run record is updated with a summary and marked COMPLETED.</li>
                </ol>
              </Accordion>

              <Accordion title="Can I run individual scanners?">
                Yes. On the{' '}
                <Link to="/scanners" className="text-tl-blue hover:underline">Scanners</Link>{' '}
                page, select a project and toggle individual scanners off. Only enabled scanners
                run on the next scan.
              </Accordion>
            </section>

            {/* ── Understanding Findings ── */}
            <section id="findings" className="scroll-mt-4">
              <div className="flex items-center gap-2 mb-4">
                <ShieldAlert size={16} className="text-tl-blue" />
                <h2 className="text-base font-semibold text-tl-text">Understanding Findings</h2>
              </div>

              <div className="space-y-3">
                <div>
                  <div className="text-xs font-semibold text-tl-muted uppercase tracking-wide mb-2">Severity</div>
                  <div className="grid grid-cols-2 sm:grid-cols-4 gap-2">
                    {[
                      { label: 'CRITICAL', color: 'bg-red-500/10 text-red-400 border-red-500/30',     desc: 'Immediate risk, likely exploitable' },
                      { label: 'HIGH',     color: 'bg-orange-500/10 text-orange-400 border-orange-500/30', desc: 'Significant impact if exploited' },
                      { label: 'MEDIUM',   color: 'bg-amber-500/10 text-amber-400 border-amber-500/30', desc: 'Moderate risk, needs attention' },
                      { label: 'LOW',      color: 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30', desc: 'Limited direct impact' },
                    ].map(({ label, color, desc }) => (
                      <div key={label} className="tl-card rounded p-2.5">
                        <StatusPill label={label} color={color} />
                        <p className="text-xs text-tl-muted mt-1.5">{desc}</p>
                      </div>
                    ))}
                  </div>
                </div>

                <div>
                  <div className="text-xs font-semibold text-tl-muted uppercase tracking-wide mb-2">Confidence</div>
                  <div className="space-y-1.5">
                    {[
                      { label: 'CONFIRMED',      color: 'bg-red-500/10 text-red-400 border-red-500/20',       desc: 'Verified by exploit or reproduction.' },
                      { label: 'LIKELY',         color: 'bg-amber-500/10 text-amber-400 border-amber-500/20', desc: 'Strong evidence; not reproduced end-to-end.' },
                      { label: 'POSSIBLE',       color: 'bg-blue-500/10 text-blue-400 border-blue-500/20',    desc: 'Code pattern found; exploitability not verified.' },
                      { label: 'FALSE_POSITIVE', color: 'bg-tl-surface2 text-tl-muted border-tl-border',      desc: 'Scanner hit a safe code path; rejected.' },
                    ].map(({ label, color, desc }) => (
                      <div key={label} className="flex items-center gap-3">
                        <StatusPill label={label} color={color} />
                        <span className="text-xs text-tl-muted">{desc}</span>
                      </div>
                    ))}
                  </div>
                </div>

                <div>
                  <div className="text-xs font-semibold text-tl-muted uppercase tracking-wide mb-1.5">CVSS Score</div>
                  <p className="text-sm text-tl-text3 leading-relaxed">
                    Every confirmed finding carries a CVSS v3.1 vector and base score. You can
                    update it from the finding detail page. The score drives severity labels and
                    risk prioritization in reports.
                  </p>
                </div>
              </div>
            </section>

            {/* ── Finding Lifecycle ── */}
            <section id="lifecycle" className="scroll-mt-4">
              <div className="flex items-center gap-2 mb-4">
                <RefreshCw size={16} className="text-tl-blue" />
                <h2 className="text-base font-semibold text-tl-text">Finding Lifecycle</h2>
              </div>

              <p className="text-sm text-tl-text3 leading-relaxed mb-4">
                Every finding travels a structured lifecycle. Each transition is recorded in the
                history log with a timestamp and actor.
              </p>

              <div className="space-y-2">
                {[
                  { icon: Clock,        status: 'DETECTED',    color: 'text-tl-muted',    desc: 'Scanner identified a potential issue. Awaiting triage.' },
                  { icon: Activity,     status: 'VALIDATING',  color: 'text-amber-400',   desc: 'Analyst is reviewing evidence and assessing confidence.' },
                  { icon: AlertTriangle,status: 'CONFIRMED',   color: 'text-red-400',     desc: 'Validated as a real finding. Awaiting remediation.' },
                  { icon: Wrench,       status: 'REMEDIATION', color: 'text-blue-400',    desc: 'A fix has been applied. Retest pending.' },
                  { icon: RefreshCw,    status: 'RETESTING',   color: 'text-purple-400',  desc: 'Scanner re-run in progress to verify the fix.' },
                  { icon: CheckCircle2, status: 'RESOLVED',    color: 'text-emerald-400', desc: 'Fix confirmed. Finding closed.' },
                  { icon: XCircle,      status: 'REJECTED',    color: 'text-tl-muted',    desc: 'False positive or out-of-scope. Not tracked.' },
                ].map(({ icon: Icon, status, color, desc }) => (
                  <div key={status} className="flex items-start gap-3 py-2 border-b border-tl-border last:border-0">
                    <Icon size={14} className={cn(color, 'flex-shrink-0 mt-0.5')} />
                    <div>
                      <code className="text-xs font-mono text-tl-text2">{status}</code>
                      <p className="text-xs text-tl-muted mt-0.5">{desc}</p>
                    </div>
                  </div>
                ))}
              </div>

              <Accordion title="Manual resolution (scanner_id = 'manual')">
                <p className="text-tl-text3 text-sm">
                  When a finding was discovered manually rather than by an auto-scanner, no
                  automated retest is possible. In this case, record a remediation with a patch
                  diff, then trigger a retest with{' '}
                  <code className="text-xs text-tl-blue">manual_resolve: true</code> in the
                  request body. Provide notes documenting how the fix was independently verified
                  (e.g., a PoC run). The finding will transition directly to RESOLVED, and the
                  verification evidence is preserved in the history log.
                </p>
              </Accordion>
            </section>

            {/* ── Scanner Reference ── */}
            <section id="scanners" className="scroll-mt-4">
              <div className="flex items-center gap-2 mb-4">
                <Cpu size={16} className="text-tl-blue" />
                <h2 className="text-base font-semibold text-tl-text">Scanner Reference</h2>
              </div>

              <p className="text-sm text-tl-text3 mb-4 leading-relaxed">
                All scanners implement the <code className="text-xs text-tl-blue">BaseScanner</code> interface and are
                auto-discovered from <code className="text-xs text-tl-blue">backend/scanners/</code>.
                Enable or disable them per-project on the{' '}
                <Link to="/scanners" className="text-tl-blue hover:underline">Scanners</Link> page.
              </p>

              <div className="tl-card rounded-lg overflow-hidden">
                <ScannerRow
                  id="injection"
                  name="Injection Flaws"
                  desc="SQL injection, command injection, SSTI, path traversal."
                  cwes={['CWE-89', 'CWE-78', 'CWE-94']}
                />
                <ScannerRow
                  id="crypto"
                  name="Cryptography"
                  desc="Weak ciphers, insecure key sizes, MD5/SHA-1 usage, hardcoded salts."
                  cwes={['CWE-326', 'CWE-327', 'CWE-328']}
                />
                <ScannerRow
                  id="authentication"
                  name="Authentication"
                  desc="Missing auth, insecure session tokens, no rate limiting."
                  cwes={['CWE-306', 'CWE-307', 'CWE-798']}
                />
                <ScannerRow
                  id="authorization"
                  name="Authorization"
                  desc="Broken access control, IDOR, missing ownership checks."
                  cwes={['CWE-284', 'CWE-639']}
                />
                <ScannerRow
                  id="dependencies"
                  name="Dependency Audit"
                  desc="Known CVEs in npm/pip packages via lockfile analysis."
                  cwes={['CWE-1104']}
                />
                <ScannerRow
                  id="configuration"
                  name="Configuration"
                  desc="Debug mode, verbose errors, insecure defaults, CI secrets."
                  cwes={['CWE-16', 'CWE-215']}
                />
                <ScannerRow
                  id="headers"
                  name="HTTP Security Headers"
                  desc="Missing CSP, HSTS, X-Frame-Options, etc. (requires running app)."
                  cwes={['CWE-693', 'CWE-1021']}
                />
                <ScannerRow
                  id="api_security"
                  name="API Security"
                  desc="Unauthenticated endpoints, mass assignment, excessive data exposure."
                  cwes={['CWE-284', 'CWE-200']}
                />
              </div>

              <Accordion title="Adding a custom scanner">
                <ol className="list-decimal list-inside space-y-1.5 text-sm text-tl-text3">
                  <li>Create a <code className="text-xs text-tl-blue">.py</code> file under <code className="text-xs text-tl-blue">backend/scanners/&lt;category&gt;/</code>.</li>
                  <li>Subclass <code className="text-xs text-tl-blue">BaseScanner</code> from <code className="text-xs text-tl-blue">scanners.base</code>.</li>
                  <li>Implement <code className="text-xs text-tl-blue">can_scan(target)</code> and <code className="text-xs text-tl-blue">scan(target)</code>.</li>
                  <li>Decorate with <code className="text-xs text-tl-blue">@scanner_registry.register</code>.</li>
                  <li>Restart the backend — autodiscovery picks it up automatically.</li>
                </ol>
              </Accordion>
            </section>

            {/* ── Reports ── */}
            <section id="reports" className="scroll-mt-4">
              <div className="flex items-center gap-2 mb-4">
                <FileText size={16} className="text-tl-blue" />
                <h2 className="text-base font-semibold text-tl-text">Reports</h2>
              </div>

              <p className="text-sm text-tl-text3 leading-relaxed mb-3">
                Generate a PDF security assessment report from any completed scan run. Reports
                include an executive summary, severity distribution, per-finding detail with
                evidence, CVSS scores, remediation notes, and retest results.
              </p>

              <div className="space-y-3">
                <Accordion title="How to generate a report">
                  <ol className="list-decimal list-inside space-y-1.5 text-sm text-tl-text3">
                    <li>Navigate to a project and open a completed scan run.</li>
                    <li>Click <strong className="text-tl-text2">Generate Report</strong>.</li>
                    <li>The PDF is built server-side with fpdf2 and stored under <code className="text-xs text-tl-blue">backend/reports/</code>.</li>
                    <li>Download it from the Reports page or directly from the scan run view.</li>
                  </ol>
                </Accordion>

                <Accordion title="What's included in the PDF">
                  <ul className="list-disc list-inside space-y-1 text-sm text-tl-text3">
                    <li>Cover page: project name, scan date, assessor</li>
                    <li>Executive summary with finding counts by severity</li>
                    <li>Severity distribution chart</li>
                    <li>Finding table with CVSS, status, confidence</li>
                    <li>Per-finding pages: description, evidence, attack path, CVSS breakdown, remediation, retest result, history</li>
                    <li>False positives appendix (with rationale)</li>
                  </ul>
                </Accordion>
              </div>
            </section>

            {/* ── Keyboard Shortcuts ── */}
            <section id="shortcuts" className="scroll-mt-4">
              <div className="flex items-center gap-2 mb-4">
                <Crosshair size={16} className="text-tl-blue" />
                <h2 className="text-base font-semibold text-tl-text">Keyboard Shortcuts</h2>
              </div>

              <div className="tl-card rounded-lg px-4">
                <Shortcut keys={['g', 'h']} desc="Go to Dashboard" />
                <Shortcut keys={['g', 'p']} desc="Go to Projects" />
                <Shortcut keys={['g', 'f']} desc="Go to Findings" />
                <Shortcut keys={['g', 's']} desc="Go to Settings" />
                <Shortcut keys={['?']}      desc="Open this Help page" />
                <Shortcut keys={['Esc']}    desc="Close modal / go back" />
              </div>

              <p className="text-xs text-tl-muted mt-3 leading-relaxed">
                Keyboard navigation is available in all table and list views. Use{' '}
                <code className="text-tl-blue">↑ ↓</code> to move between rows and{' '}
                <code className="text-tl-blue">Enter</code> to open the selected item.
              </p>
            </section>

            {/* ── API docs link ── */}
            <div className="tl-card rounded-lg p-4 flex items-center justify-between">
              <div>
                <div className="text-sm font-medium text-tl-text">Interactive API Docs</div>
                <p className="text-xs text-tl-muted mt-0.5">
                  Explore and test every endpoint in your browser via the auto-generated Swagger UI.
                </p>
              </div>
              <a
                href="http://localhost:8000/docs"
                target="_blank"
                rel="noopener noreferrer"
                className="tl-btn-secondary flex-shrink-0"
              >
                Open docs
                <ExternalLink size={12} />
              </a>
            </div>

          </div>
        </div>
      </div>
    </div>
  )
}
