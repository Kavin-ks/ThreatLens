import { LucideIcon } from 'lucide-react'

interface EmptyStateProps {
  icon: LucideIcon
  title: string
  description: string
  action?: React.ReactNode
}

export function EmptyState({ icon: Icon, title, description, action }: EmptyStateProps) {
  return (
    <div className="flex flex-col items-center justify-center py-16 px-4 text-center">
      <div className="flex items-center justify-center w-14 h-14 rounded-2xl bg-tl-surface2 border border-tl-border mb-4">
        <Icon size={24} className="text-tl-muted" />
      </div>
      <h3 className="text-sm font-semibold text-tl-text2 mb-1">{title}</h3>
      <p className="text-sm text-tl-muted max-w-xs leading-relaxed mb-5">{description}</p>
      {action}
    </div>
  )
}
