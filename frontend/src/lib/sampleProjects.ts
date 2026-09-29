import type { Project, ProjectSummary, Finding, ScanRun } from '../types'

export const SAMPLE_PROJECTS: ProjectSummary[] = [
  {
    id: '11111111-2222-3333-4444-555555555555',
    name: 'ThreatLens Security Assessment',
    description: 'Evidence-driven application security assessment for World Monitor application — NTRO Problem Statement.',
    status: 'active',
    total_findings: 18,
    confirmed_findings: 14,
    critical_count: 3,
    high_count: 8,
    last_scan_at: new Date(Date.now() - 3600000).toISOString(),
    created_at: new Date(Date.now() - 86400000).toISOString(),
  },
  {
    id: '22222222-3333-4444-5555-666666666666',
    name: 'LedgerLens - Blockchain Forensic & AML Analysis',
    description: 'Multi-chain fraud tracing, AML transaction tracking, and smart contract security audit.',
    status: 'active',
    total_findings: 12,
    confirmed_findings: 9,
    critical_count: 2,
    high_count: 4,
    last_scan_at: new Date(Date.now() - 7200000).toISOString(),
    created_at: new Date(Date.now() - 172800000).toISOString(),
  },
]

export const SAMPLE_PROJECT_DETAILS: Record<string, Project> = {
  '11111111-2222-3333-4444-555555555555': {
    id: '11111111-2222-3333-4444-555555555555',
    name: 'ThreatLens Security Assessment',
    description: 'Evidence-driven application security assessment for World Monitor application — NTRO Problem Statement.',
    target_path: 'C:/Users/priya/jeeva_project/sih2/ThreatLens',
    target_url: 'http://localhost:8000',
    status: 'active',
    stack_info: JSON.stringify({
      languages: ['Python', 'TypeScript', 'JavaScript'],
      frameworks: ['FastAPI', 'React', 'Vite', 'Tailwind CSS'],
      package_managers: ['pip', 'npm'],
    }),
    created_at: new Date(Date.now() - 86400000).toISOString(),
    updated_at: new Date(Date.now() - 3600000).toISOString(),
  },
  '22222222-3333-4444-5555-666666666666': {
    id: '22222222-3333-4444-5555-666666666666',
    name: 'LedgerLens - Blockchain Forensic & AML Analysis',
    description: 'Multi-chain fraud tracing, AML transaction tracking, and smart contract security audit.',
    target_path: 'C:/Users/priya/jeeva_project/LedgerLens',
    target_url: 'http://localhost:3000',
    status: 'active',
    stack_info: JSON.stringify({
      languages: ['Solidity', 'TypeScript', 'Python'],
      frameworks: ['Hardhat', 'FastAPI', 'React', 'Next.js'],
      package_managers: ['npm', 'pip'],
    }),
    created_at: new Date(Date.now() - 172800000).toISOString(),
    updated_at: new Date(Date.now() - 7200000).toISOString(),
  },
}
