import { cn } from '../../lib/utils'
import type { Severity } from '../../types'

const CONFIG: Record<Severity, { label: string; classes: string }> = {
  CRITICAL: { label: 'CRITICAL', classes: 'bg-red-500 bg-opacity-15 text-red-400 border-red-500 border-opacity-30' },
  HIGH:     { label: 'HIGH',     classes: 'bg-orange-500 bg-opacity-15 text-orange-400 border-orange-500 border-opacity-30' },
  MEDIUM:   { label: 'MEDIUM',   classes: 'bg-yellow-500 bg-opacity-15 text-yellow-400 border-yellow-500 border-opacity-30' },
  LOW:      { label: 'LOW',      classes: 'bg-emerald-500 bg-opacity-15 text-emerald-400 border-emerald-500 border-opacity-30' },
  INFO:     { label: 'INFO',     classes: 'bg-tl-surface3 text-tl-muted border-tl-border' },
}

interface Props {
  severity: Severity
  size?: 'sm' | 'md'
}

export function SeverityBadge({ severity, size = 'sm' }: Props) {
  const { label, classes } = CONFIG[severity] ?? CONFIG.INFO
  return (
    <span
      className={cn(
        'inline-flex items-center font-mono font-semibold border rounded',
        size === 'sm' ? 'text-[10px] px-1.5 py-0.5 tracking-wider' : 'text-xs px-2 py-1',
        classes
      )}
    >
      {label}
    </span>
  )
}
