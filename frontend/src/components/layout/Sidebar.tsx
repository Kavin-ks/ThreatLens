import { NavLink, useLocation } from 'react-router-dom'
import {
  LayoutDashboard,
  FolderOpen,
  ShieldAlert,
  Activity,
  FileText,
  Cpu,
  Settings,
  ChevronRight,
  Crosshair,
  HelpCircle,
} from 'lucide-react'
import { cn } from '../../lib/utils'

interface NavItem {
  label: string
  to: string
  icon: React.ComponentType<{ className?: string; size?: number }>
}

const navSections: { heading?: string; items: NavItem[] }[] = [
  {
    items: [
      { label: 'Dashboard', to: '/', icon: LayoutDashboard },
      { label: 'Projects', to: '/projects', icon: FolderOpen },
    ],
  },
  {
    heading: 'Assessment',
    items: [
      { label: 'Findings', to: '/findings', icon: ShieldAlert },
      { label: 'Scans', to: '/scans', icon: Activity },
      { label: 'Reports', to: '/reports', icon: FileText },
    ],
  },
  {
    heading: 'Configuration',
    items: [
      { label: 'Scanners', to: '/scanners', icon: Cpu },
      { label: 'Settings', to: '/settings', icon: Settings },
    ],
  },
  {
    heading: 'Support',
    items: [
      { label: 'Help & Guide', to: '/help', icon: HelpCircle },
    ],
  },
]

export function Sidebar() {
  const location = useLocation()

  return (
    <aside className="flex flex-col w-60 min-w-60 h-screen bg-tl-surface border-r border-tl-border overflow-y-auto">
      {/* Logo */}
      <div className="flex items-center gap-2.5 px-4 py-5 border-b border-tl-border">
        <div className="flex items-center justify-center w-8 h-8 rounded-lg bg-tl-blue/20 border border-tl-blue/30">
          <Crosshair size={16} className="text-tl-blue" />
        </div>
        <div>
          <span className="font-semibold text-tl-text font-mono tracking-tight text-sm">
            ThreatLens
          </span>
          <div className="text-[10px] text-tl-muted font-mono">v1.0.0</div>
        </div>
      </div>

      {/* Navigation */}
      <nav className="flex-1 px-2 py-4 space-y-5">
        {navSections.map((section, i) => (
          <div key={i}>
            {section.heading && (
              <div className="section-header px-2 mb-1.5">{section.heading}</div>
            )}
            <div className="space-y-0.5">
              {section.items.map((item) => {
                const isActive =
                  item.to === '/'
                    ? location.pathname === '/'
                    : location.pathname.startsWith(item.to)

                return (
                  <NavLink
                    key={item.to}
                    to={item.to}
                    className={cn(
                      'flex items-center gap-2.5 px-3 py-2 rounded-md text-sm transition-colors group',
                      isActive
                        ? 'bg-tl-blue/15 text-tl-blue font-medium'
                        : 'text-tl-text3 hover:text-tl-text2 hover:bg-tl-surface2'
                    )}
                  >
                    <item.icon
                      size={15}
                      className={cn(
                        'flex-shrink-0',
                        isActive ? 'text-tl-blue' : 'text-tl-muted group-hover:text-tl-text3'
                      )}
                    />
                    <span className="flex-1">{item.label}</span>
                    {isActive && (
                      <ChevronRight size={12} className="text-tl-blue opacity-60" />
                    )}
                  </NavLink>
                )
              })}
            </div>
          </div>
        ))}
      </nav>

      {/* Footer */}
      <div className="px-4 py-3 border-t border-tl-border">
        <div className="text-[11px] text-tl-muted leading-relaxed">
          <div className="font-mono">SIH 2026 · NTRO</div>
          <div>Authorized assessments only</div>
        </div>
      </div>
    </aside>
  )
}
