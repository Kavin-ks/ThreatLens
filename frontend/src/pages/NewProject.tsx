import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { useMutation, useQueryClient } from '@tanstack/react-query'
import { ArrowLeft, FolderOpen, Globe, AlertCircle } from 'lucide-react'
import { TopBar } from '../components/layout/TopBar'
import { projectsApi } from '../api/endpoints'

export default function NewProject() {
  const navigate = useNavigate()
  const queryClient = useQueryClient()

  const [form, setForm] = useState({
    name: '',
    description: '',
    target_path: '',
    target_url: '',
  })
  const [error, setError] = useState<string | null>(null)

  const mutation = useMutation({
    mutationFn: projectsApi.create,
    onSuccess: (project) => {
      queryClient.invalidateQueries({ queryKey: ['projects'] })
      navigate(`/projects/${project.id}`)
    },
    onError: (err: Error) => {
      setError(err.message)
    },
  })

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault()
    setError(null)
    if (!form.name.trim()) {
      setError('Project name is required.')
      return
    }
    mutation.mutate({
      name: form.name.trim(),
      description: form.description.trim() || undefined,
      target_path: form.target_path.trim() || undefined,
      target_url: form.target_url.trim() || undefined,
    })
  }

  return (
    <div className="flex flex-col h-full">
      <TopBar
        title="New Assessment"
        subtitle="Set up a new security assessment project"
        actions={
          <button
            onClick={() => navigate(-1)}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-md text-tl-muted hover:text-tl-text2 hover:bg-tl-surface2 text-xs transition-colors"
          >
            <ArrowLeft size={13} />
            Back
          </button>
        }
      />

      <div className="flex-1 overflow-y-auto p-6">
        <div className="max-w-xl">
          <form onSubmit={handleSubmit} className="space-y-5">
            {error && (
              <div className="flex items-start gap-2 px-4 py-3 rounded-lg bg-red-500 bg-opacity-10 border border-red-500 border-opacity-30 text-sm text-red-400">
                <AlertCircle size={15} className="flex-shrink-0 mt-0.5" />
                <span>{error}</span>
              </div>
            )}

            {/* Project name */}
            <div>
              <label className="block text-xs font-medium text-tl-text2 mb-1.5">
                Project Name <span className="text-red-400">*</span>
              </label>
              <input
                type="text"
                value={form.name}
                onChange={(e) => setForm((f) => ({ ...f, name: e.target.value }))}
                placeholder="e.g. World Monitor Security Assessment"
                className="w-full bg-tl-surface border border-tl-border rounded-md px-3 py-2 text-sm text-tl-text placeholder:text-tl-muted focus:outline-none focus:border-tl-blue focus:ring-1 focus:ring-tl-blue focus:ring-opacity-30 transition-colors"
                required
              />
            </div>

            {/* Description */}
            <div>
              <label className="block text-xs font-medium text-tl-text2 mb-1.5">
                Description <span className="text-tl-muted">(optional)</span>
              </label>
              <textarea
                value={form.description}
                onChange={(e) => setForm((f) => ({ ...f, description: e.target.value }))}
                placeholder="Brief description of the assessment scope…"
                rows={3}
                className="w-full bg-tl-surface border border-tl-border rounded-md px-3 py-2 text-sm text-tl-text placeholder:text-tl-muted focus:outline-none focus:border-tl-blue focus:ring-1 focus:ring-tl-blue focus:ring-opacity-30 transition-colors resize-none"
              />
            </div>

            {/* Target path */}
            <div>
              <label className="block text-xs font-medium text-tl-text2 mb-1.5 flex items-center gap-1.5">
                <FolderOpen size={12} className="text-tl-muted" />
                Target Path <span className="text-tl-muted">(local source directory)</span>
              </label>
              <input
                type="text"
                value={form.target_path}
                onChange={(e) => setForm((f) => ({ ...f, target_path: e.target.value }))}
                placeholder="/path/to/world-monitor"
                className="w-full bg-tl-surface border border-tl-border rounded-md px-3 py-2 text-sm text-tl-text font-mono placeholder:text-tl-muted focus:outline-none focus:border-tl-blue focus:ring-1 focus:ring-tl-blue focus:ring-opacity-30 transition-colors"
              />
            </div>

            {/* Target URL */}
            <div>
              <label className="block text-xs font-medium text-tl-text2 mb-1.5 flex items-center gap-1.5">
                <Globe size={12} className="text-tl-muted" />
                Target URL <span className="text-tl-muted">(local running instance)</span>
              </label>
              <input
                type="url"
                value={form.target_url}
                onChange={(e) => setForm((f) => ({ ...f, target_url: e.target.value }))}
                placeholder="http://localhost:8080"
                className="w-full bg-tl-surface border border-tl-border rounded-md px-3 py-2 text-sm text-tl-text font-mono placeholder:text-tl-muted focus:outline-none focus:border-tl-blue focus:ring-1 focus:ring-tl-blue focus:ring-opacity-30 transition-colors"
              />
              <p className="text-xs text-tl-muted mt-1.5">
                Only point to a local, authorized instance. Never use production or third-party URLs.
              </p>
            </div>

            {/* Actions */}
            <div className="flex items-center gap-3 pt-2">
              <button
                type="submit"
                disabled={mutation.isPending}
                className="flex items-center gap-1.5 px-4 py-2 rounded-md bg-tl-blue text-white text-sm font-medium hover:bg-tl-blue2 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
              >
                {mutation.isPending ? 'Creating…' : 'Create Assessment'}
              </button>
              <button
                type="button"
                onClick={() => navigate(-1)}
                className="px-4 py-2 rounded-md text-tl-muted hover:text-tl-text2 hover:bg-tl-surface2 text-sm transition-colors"
              >
                Cancel
              </button>
            </div>
          </form>
        </div>
      </div>
    </div>
  )
}
