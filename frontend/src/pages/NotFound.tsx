import { Link } from 'react-router-dom'
import { ArrowLeft, SearchX } from 'lucide-react'

export default function NotFound() {
  return (
    <div className="flex flex-col items-center justify-center h-screen text-center px-4">
      <SearchX size={40} className="text-tl-muted mb-4" />
      <h1 className="text-lg font-semibold text-tl-text2 mb-1">Page not found</h1>
      <p className="text-sm text-tl-muted mb-6">
        The page you're looking for doesn't exist or has been moved.
      </p>
      <Link
        to="/"
        className="flex items-center gap-1.5 text-sm text-tl-blue hover:underline"
      >
        <ArrowLeft size={13} />
        Back to Dashboard
      </Link>
    </div>
  )
}
