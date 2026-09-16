import { createBrowserRouter, RouterProvider } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import AppLayout from './components/layout/AppLayout'
import Dashboard from './pages/Dashboard'
import Projects from './pages/Projects'
import NewProject from './pages/NewProject'
import NotFound from './pages/NotFound'

const router = createBrowserRouter([
  {
    path: '/',
    element: <AppLayout />,
    children: [
      { index: true, element: <Dashboard /> },
      { path: 'projects', element: <Projects /> },
      { path: 'projects/new', element: <NewProject /> },
      { path: 'projects/:id', element: <Dashboard /> }, // Placeholder — Phase 5
      { path: 'findings', element: <Dashboard /> },      // Placeholder — Phase 5
      { path: 'scans', element: <Dashboard /> },         // Placeholder — Phase 5
      { path: 'reports', element: <Dashboard /> },       // Placeholder — Phase 7
      { path: 'scanners', element: <Dashboard /> },      // Placeholder — Phase 3
      { path: 'settings', element: <Dashboard /> },      // Placeholder
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
