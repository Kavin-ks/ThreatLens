import { createBrowserRouter, RouterProvider } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import AppLayout from './components/layout/AppLayout'
import Dashboard from './pages/Dashboard'
import Projects from './pages/Projects'
import NewProject from './pages/NewProject'
import ProjectDetail from './pages/ProjectDetail'
import ScanDetail from './pages/ScanDetail'
import FindingDetail from './pages/FindingDetail'
import NotFound from './pages/NotFound'

const router = createBrowserRouter([
  {
    path: '/',
    element: <AppLayout />,
    children: [
      { index: true, element: <Dashboard /> },
      { path: 'projects', element: <Projects /> },
      { path: 'projects/new', element: <NewProject /> },
      { path: 'projects/:id', element: <ProjectDetail /> },
      { path: 'projects/:id/scans/:scanId', element: <ScanDetail /> },
      { path: 'projects/:id/findings/:findingId', element: <FindingDetail /> },
      { path: 'findings', element: <Dashboard /> },  // Global: falls back to dashboard
      { path: 'scans', element: <Dashboard /> },
      { path: 'reports', element: <Dashboard /> },   // Phase 6
      { path: 'scanners', element: <Dashboard /> },
      { path: 'settings', element: <Dashboard /> },
    ],
  },
  { path: '*', element: <NotFound /> },
])

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      staleTime: 30_000,
      retry: 1,
    },
  },
})

export default function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <RouterProvider router={router} />
    </QueryClientProvider>
  )
}
