import { HelpCircle, Bell } from 'lucide-react'

interface TopBarProps {
  title: string
  subtitle?: string
  actions?: React.ReactNode
}

export function TopBar({ title, subtitle, actions }: TopBarProps) {
  return (
    <header className="flex items-center justify-between px-6 py-4 border-b border-tl-border bg-tl-surface flex-shrink-0">
      <div>
        <h1 className="text-base font-semibold text-tl-text leading-tight">{title}</h1>
        {subtitle && (
          <p className="text-xs text-tl-muted mt-0.5">{subtitle}</p>
        )}
      </div>
      <div className="flex items-center gap-2">
        {actions}
        <button
          className="p-2 rounded-md text-tl-muted hover:text-tl-text2 hover:bg-tl-surface2 transition-colors"
          title="Help"
        >
          <HelpCircle size={16} />
        </button>
        <button
          className="p-2 rounded-md text-tl-muted hover:text-tl-text2 hover:bg-tl-surface2 transition-colors"
          title="Notifications"
        >
          <Bell size={16} />
        </button>
      </div>
    </header>
  )
}
