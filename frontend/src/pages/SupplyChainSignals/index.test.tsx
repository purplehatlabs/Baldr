// @vitest-environment jsdom

import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import '@testing-library/jest-dom/vitest'
import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { describe, expect, it, vi } from 'vitest'
import * as supplyChainSignalsApi from '@/api/supplyChainSignals'
import SupplyChainSignalsPage from './index'

vi.mock('@/api/repos', () => ({
  listRepos: vi.fn(async () => [
    {
      id: 'repo-1',
      full_name: 'org-a/repo-a',
      org_id: 'org-1',
      github_repo_id: 1001,
      default_branch: 'main',
      is_archived: false,
      is_monorepo: false,
      created_at: new Date().toISOString(),
    },
  ]),
}))

vi.mock('@/api/supplyChainSignals', () => ({
  listSupplyChainSignals: vi.fn(async () => ({
    items: [
      {
        id: 'signal-1',
        repo_id: 'repo-1',
        repo_full_name: 'org-a/repo-a',
        package_ecosystem: 'npm',
        package_name: 'left-pad',
        package_version: '1.0.0',
        signal_type: 'malicious_package',
        status: 'open',
        severity: 'critical',
        source_engine: 'dataset',
        signal_key: 'MAL-2026-001',
        confidence: 1,
        reasoning: 'known malicious package',
        first_seen_at: new Date().toISOString(),
        last_seen_at: new Date().toISOString(),
      },
    ],
    total: 1,
    page: 1,
    per_page: 20,
    total_pages: 1,
  })),
  getSupplyChainSignalsSummary: vi.fn(async () => ({
    total: 1,
    by_status: { open: 1 },
    by_severity: { critical: 1 },
    by_engine: { dataset: 1 },
    by_signal_type: { malicious_package: 1 },
  })),
  getSupplyChainSignalById: vi.fn(async () => ({
    id: 'signal-1',
    repo_id: 'repo-1',
    repo_full_name: 'org-a/repo-a',
    package_ecosystem: 'npm',
    package_name: 'left-pad',
    package_version: '1.0.0',
    signal_type: 'malicious_package',
    status: 'open',
    severity: 'critical',
    source_engine: 'dataset',
    signal_key: 'MAL-2026-001',
    confidence: 1,
    reasoning: 'known malicious package',
    evidence_json: {
      source: 'openssf-malicious-packages',
      external_id: 'MAL-2026-001',
    },
    metadata_json: {
      source: 'openssf-malicious-packages',
    },
  })),
}))

function renderPage() {
  const queryClient = new QueryClient({
    defaultOptions: {
      queries: {
        retry: false,
      },
    },
  })
  return render(
    <QueryClientProvider client={queryClient}>
      <SupplyChainSignalsPage />
    </QueryClientProvider>,
  )
}

describe('SupplyChainSignalsPage flow', () => {
  it('renders list and opens detail with evidence', async () => {
    renderPage()

    await waitFor(() => {
      expect(screen.getByText('left-pad')).toBeInTheDocument()
    })

    fireEvent.click(screen.getByText('left-pad'))

    await waitFor(() => {
      expect(screen.getByText('Evidence JSON')).toBeInTheDocument()
    })

    await waitFor(() => {
      expect(vi.mocked(supplyChainSignalsApi.getSupplyChainSignalById)).toHaveBeenCalledWith('signal-1')
    })
  })
})

