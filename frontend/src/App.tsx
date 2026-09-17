import { createBrowserRouter, RouterProvider } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import AppLayout from './components/layout/AppLayout'
import Dashboard from './pages/Dashboard'
import Projects from './pages/Projects'
import NewProject from './pages/NewProject'
import ProjectDetail from './pages/ProjectDetail'
import ScanDetail from './pages/ScanDetail'
import FindingDetail from './pages/FindingDetail'
import GlobalFindings from './pages/GlobalFindings'
import GlobalScans from './pages/GlobalScans'
import Scanners from './pages/Scanners'
import Settings from './pages/Settings'
import Help from './pages/Help'
import NotFound from './pages/NotFound'

const router = createBrowserRouter([
  {
    path: '/',
    element: <AppLayout />,
    children: [
      { index: true,                                          element: <Dashboard /> },
      { path: 'projects',                                     element: <Projects /> },
      { path: 'projects/new',                                 element: <NewProject /> },
      { path: 'projects/:id',                                 element: <ProjectDetail /> },
      { path: 'projects/:id/scans/:scanId',                   element: <ScanDetail /> },
      { path: 'projects/:id/findings/:findingId',             element: <FindingDetail /> },
      { path: 'findings',                                     element: <GlobalFindings /> },
      { path: 'scans',                                        element: <GlobalScans /> },
      { path: 'reports',                                      element: <Dashboard /> },
      { path: 'scanners',                                     element: <Scanners /> },
      { path: 'settings',                                     element: <Settings /> },
      { path: 'help',                                         element: <Help /> },
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
