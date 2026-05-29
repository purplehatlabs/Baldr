# Frontend — Development Guide (React)

## Stack

| Package | Version | Role |
|---|---|---|
| React | 18 | UI |
| TypeScript | 5 | Types |
| Vite | 5 | Bundler + dev server |
| React Router | v6 | SPA routing |
| TanStack Query | v5 | Fetch, cache, and mutations |
| Axios | 1 | HTTP client (via `src/api/client.ts`) |
| Tailwind CSS | 3 | Utility-first styling |
| Recharts | 2 | Charts |
| lucide-react | 0.408 | Icons |

## Structure

```
frontend/src/
├── api/                  # Fetch functions + domain types
│   ├── client.ts         # axios instance with cookies and 401 interceptor
│   ├── auth.ts           # getMe, logout, devLogin, isDevAuthEnabled
│   ├── dashboard.ts      # getDashboard → DashboardSummary
│   ├── orgs.ts           # listOrgs, createOrg, deleteOrg → Org
│   ├── repos.ts          # listRepos, triggerScan, listScanJobs → Repo, ScanJob
│   ├── findings.ts       # listFindings, getFinding, updateFindingStatus → Finding
│   └── teams.ts          # listTeams, getTeamFindings → Team
├── components/
│   ├── layout/
│   │   ├── AppLayout.tsx  # Wrapper with Sidebar + Header + <Outlet />
│   │   ├── Sidebar.tsx    # Side navigation
│   │   └── Header.tsx     # Topbar with user info + logout
│   └── shared/
│       ├── SeverityBadge.tsx  # Coloured badge by severity + severityOrder/Color
│       ├── StatusBadge.tsx    # Finding status badge
│       ├── EmptyState.tsx     # Reusable empty state
│       └── Spinner.tsx        # Spinner + PageSpinner
├── hooks/
│   └── useAuth.ts         # useQuery(['auth','me']) + logout mutation
├── lib/
│   └── utils.ts           # cn() = clsx + tailwind-merge
└── pages/
    ├── Login/index.tsx     # Login screen (GitHub/Google OAuth + dev form)
    ├── Dashboard/index.tsx # Metrics and bar chart
    ├── Repositories/       # Repo list, manual scan
    ├── Findings/           # Filtered table + detail panel
    ├── Teams/              # Expandable cards per team
    └── Settings/           # Manage GitHub orgs
```

## Adding a new page

### 1. Create the folder and component

```tsx
// src/pages/Widgets/index.tsx
import { useQuery } from '@tanstack/react-query'
import { listWidgets } from '@/api/widgets'
import { PageSpinner } from '@/components/shared/Spinner'
import { EmptyState } from '@/components/shared/EmptyState'
import { Box } from 'lucide-react'

export default function WidgetsPage() {
  const { data: widgets = [], isLoading } = useQuery({
    queryKey: ['widgets'],
    queryFn: listWidgets,
  })

  if (isLoading) return <PageSpinner />
  if (widgets.length === 0) {
    return (
      <div className="bg-white rounded-xl border border-gray-200">
        <EmptyState icon={Box} title="No widgets" description="Create a widget to get started." />
      </div>
    )
  }

  return <div>{/* content */}</div>
}
```

### 2. Create the API client

```ts
// src/api/widgets.ts
import { api } from './client'

export interface Widget {
  id: string
  name: string
  created_at: string
}

export async function listWidgets(): Promise<Widget[]> {
  const { data } = await api.get<Widget[]>('/api/v1/widgets')
  return data
}
```

### 3. Register in the router

```tsx
// src/App.tsx — inside <Route element={<ProtectedRoutes />}>
import WidgetsPage from '@/pages/Widgets'

<Route path="/widgets" element={<WidgetsPage />} />
```

### 4. Add item to the sidebar

```tsx
// src/components/layout/Sidebar.tsx — navItems array
{ to: '/widgets', icon: Box, label: 'Widgets' },
```

## Component patterns

### Data fetching (TanStack Query)

```tsx
// Simple query
const { data, isLoading, error } = useQuery({
  queryKey: ['widgets'],       // array — include filters that affect the result
  queryFn: listWidgets,
  refetchInterval: 30_000,     // optional polling
})

// Query with parameter
const { data } = useQuery({
  queryKey: ['widgets', id],
  queryFn: () => getWidget(id),
  enabled: !!id,               // only runs when id exists
})

// Mutation
const mutation = useMutation({
  mutationFn: deleteWidget,
  onSuccess: () => {
    queryClient.invalidateQueries({ queryKey: ['widgets'] })
  },
})
```

### Forms

No form library — simple controlled HTML is enough:

```tsx
const [name, setName] = useState('')

const mutation = useMutation({
  mutationFn: (name: string) => createWidget(name),
  onSuccess: () => { setName(''); onClose() },
})

<form onSubmit={(e) => { e.preventDefault(); mutation.mutate(name) }}>
  <input value={name} onChange={(e) => setName(e.target.value)} required />
  <button type="submit" disabled={mutation.isPending}>
    {mutation.isPending ? 'Saving…' : 'Save'}
  </button>
</form>
```

### Styling with Tailwind

Use the `cn()` function from `src/lib/utils.ts` for conditional classes:

```tsx
import { cn } from '@/lib/utils'

// Conditional class
<div className={cn('px-4 py-2 rounded-lg', isActive && 'bg-brand-600 text-white')} />

// Variants
<span className={cn(
  'text-xs font-medium px-2 py-0.5 rounded-full',
  variant === 'error' && 'bg-red-100 text-red-700',
  variant === 'success' && 'bg-green-100 text-green-700',
)} />
```

### Severity colours

Always use the constants from `SeverityBadge.tsx` for consistency:

```tsx
import { SeverityBadge, severityColor, severityOrder } from '@/components/shared/SeverityBadge'

// Visual badge
<SeverityBadge severity={finding.severity} />
<SeverityBadge severity="critical" size="sm" />

// For Recharts charts
fill={severityColor[severity]}  // "#ef4444" for critical

// For sorting
findings.sort((a, b) => severityOrder[a.severity] - severityOrder[b.severity])
```

## HTTP client

Never use axios or fetch directly in pages — always go through `src/api/*.ts`:

```ts
// src/api/client.ts — already configured with:
// - baseURL from VITE_API_BASE_URL
// - withCredentials: true (sends httpOnly cookies)
// - interceptor: redirects to /login on 401
import { api } from './client'

export async function createWidget(name: string): Promise<Widget> {
  const { data } = await api.post<Widget>('/api/v1/widgets', { name })
  return data
}
```

## Environment variables (Vite)

Required `VITE_` prefix to expose variables to the browser:

```ts
// Access in TypeScript code
import.meta.env.VITE_API_BASE_URL    // string | undefined
import.meta.env.VITE_DEV_AUTH_ENABLED // string | undefined
```

Defined in `.env` and passed by Docker Compose via `environment:`.

## Authentication state

```tsx
import { useAuth } from '@/hooks/useAuth'

function MyComponent() {
  const { user, isAuthenticated, isLoading, logout } = useAuth()
  // user: User | undefined
  // isAuthenticated: boolean
}
```

`useAuth` uses `queryKey: ['auth', 'me']`. To force a re-fetch after login:
```tsx
queryClient.invalidateQueries({ queryKey: ['auth', 'me'] })
```

## Tests

- Framework: **Vitest** (already in `package.json`)
- For components: **@testing-library/react**
- File convention: `Component.test.tsx` next to the component
- Mock API: `vi.mock('@/api/findings')`

```tsx
// Example
import { render, screen } from '@testing-library/react'
import { SeverityBadge } from './SeverityBadge'

test('displays correct label for critical', () => {
  render(<SeverityBadge severity="critical" />)
  expect(screen.getByText('Critical')).toBeInTheDocument()
})
```
