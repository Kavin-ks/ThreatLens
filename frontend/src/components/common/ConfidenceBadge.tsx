import { cn } from '../../lib/utils'
import type { Confidence } from '../../types'

const CONFIG: Record<Confidence, { label: string; classes: string }> = {
  CONFIRMED:      { label: 'CONFIRMED',  classes: 'bg-red-500 bg-opacity-15 text-red-400 border-red-500 border-opacity-30' },
  LIKELY:         { label: 'LIKELY',     classes: 'bg-orange-500 bg-opacity-15 text-orange-400 border-orange-500 border-opacity-30' },
  POSSIBLE:       { label: 'POSSIBLE',   classes: 'bg-yellow-500 bg-opacity-15 text-yellow-400 border-yellow-500 border-opacity-30' },
  FALSE_POSITIVE: { label: 'FP',         classes: 'bg-tl-surface3 text-tl-muted border-tl-border' },
}

interface Props {
  confidence: Confidence
  size?: 'sm' | 'md'
}

export function ConfidenceBadge({ confidence, size = 'sm' }: Props) {
  const { label, classes } = CONFIG[confidence] ?? CONFIG.POSSIBLE
  return (
    <span
      className={cn(
        'inline-flex items-center font-mono font-medium border rounded',
        size === 'sm' ? 'text-[10px] px-1.5 py-0.5 tracking-wider' : 'text-xs px-2 py-1',
        classes
      )}
    >
      {label}
    </span>
  )
}
