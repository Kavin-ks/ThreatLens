import { cn } from '../../lib/utils'
import type { FindingStatus } from '../../types'

const CONFIG: Record<FindingStatus, { label: string; dotClass: string; textClass: string }> = {
  DETECTED:    { label: 'Detected',    dotClass: 'bg-tl-muted',   textClass: 'text-tl-muted' },
  VALIDATING:  { label: 'Validating',  dotClass: 'bg-tl-blue animate-pulse',    textClass: 'text-tl-blue' },
  CONFIRMED:   { label: 'Confirmed',   dotClass: 'bg-red-400',    textClass: 'text-red-400' },
  REJECTED:    { label: 'Rejected',    dotClass: 'bg-tl-muted',   textClass: 'text-tl-muted line-through' },
  REMEDIATION: { label: 'Remediation', dotClass: 'bg-yellow-400', textClass: 'text-yellow-400' },
  RETESTING:   { label: 'Retesting',   dotClass: 'bg-tl-purple animate-pulse',  textClass: 'text-tl-purple' },
  RESOLVED:    { label: 'Resolved',    dotClass: 'bg-emerald-400', textClass: 'text-emerald-400' },
}

interface Props {
  status: FindingStatus
}

export function StatusBadge({ status }: Props) {
  const { label, dotClass, textClass } = CONFIG[status] ?? CONFIG.DETECTED
  return (
    <span className="inline-flex items-center gap-1.5">
      <span className={cn('w-1.5 h-1.5 rounded-full flex-shrink-0', dotClass)} />
      <span className={cn('text-xs font-medium', textClass)}>{label}</span>
    </span>
  )
}
