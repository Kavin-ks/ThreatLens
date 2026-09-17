import { Link } from 'react-router-dom'
import { HelpCircle, Bell, Sun, Moon } from 'lucide-react'
import { useTheme } from '../../context/ThemeContext'

interface TopBarProps {
  title: string
  subtitle?: string
  actions?: React.ReactNode
}

export function TopBar({ title, subtitle, actions }: TopBarProps) {
  const { theme, toggleTheme } = useTheme()

  return (
    <header className="flex items-center justify-between px-6 py-4 border-b border-tl-border bg-tl-surface flex-shrink-0">
      <div>
        <h1 className="text-base font-semibold text-tl-text leading-tight">{title}</h1>
        {subtitle && (
          <p className="text-xs text-tl-muted mt-0.5">{subtitle}</p>
        )}
      </div>

      <div className="flex items-center gap-1">
        {actions && <div className="mr-2">{actions}</div>}

        <button
          onClick={toggleTheme}
          className="p-2 rounded-md text-tl-muted hover:text-tl-text2 hover:bg-tl-surface2 transition-colors"
          title={theme === 'dark' ? 'Switch to light mode' : 'Switch to dark mode'}
          aria-label="Toggle theme"
        >
          {theme === 'dark' ? <Sun size={16} /> : <Moon size={16} />}
        </button>

        <Link
          to="/help"
          className="p-2 rounded-md text-tl-muted hover:text-tl-text2 hover:bg-tl-surface2 transition-colors"
          title="Help & documentation"
          aria-label="Help"
        >
          <HelpCircle size={16} />
        </Link>

        <button
          className="p-2 rounded-md text-tl-muted hover:text-tl-text2 hover:bg-tl-surface2 transition-colors"
          title="Notifications"
          aria-label="Notifications"
        >
          <Bell size={16} />
        </button>
      </div>
    </header>
  )
}
