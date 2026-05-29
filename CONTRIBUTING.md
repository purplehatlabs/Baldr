# Contributing to Baldr

Thank you for your interest in contributing! Baldr is an open-source SCA platform — every contribution helps the community.

## Getting started

1. Fork the repository
2. Clone your fork: `git clone https://github.com/YOUR_USERNAME/baldr.git`
3. Copy the environment file: `cp .env.example .env`
4. Start the dev environment: `make dev`

See the [README](README.md) for full setup instructions.

## How to contribute

### Reporting bugs

Open an issue using the **Bug Report** template. Include:
- Steps to reproduce
- Expected vs. actual behavior
- Environment (OS, Go version, Node version, Docker version)
- Relevant logs (`make logs`)

### Suggesting features

Open an issue using the **Feature Request** template. Describe the use case clearly — what problem does it solve?

### Pull requests

1. Create a branch from `main`: `git checkout -b feat/your-feature`
2. Make your changes following the conventions below
3. Run tests: `make test`
4. Verify the build compiles: `cd backend && go build ./...`
5. Verify TypeScript: `cd frontend && node_modules/.bin/tsc --noEmit`
6. Open a PR against `main`

Keep PRs focused — one feature or fix per PR. Link the related issue.

## Code conventions

### Backend (Go)

- No ORM — raw SQL with `pgx/v5`
- Every query on user data **must** filter by `tenant_id`
- New HTTP handlers go in `internal/api/routes/`, registered in `cmd/api/main.go`
- New DB tables need a migration in `internal/db/migrations/` (`.up.sql` + `.down.sql`)
- New domain types go in `internal/models/models.go`

### Frontend (React)

- Data fetching via TanStack Query (`useQuery` / `useMutation`)
- HTTP calls via `src/api/client.ts` (axios instance)
- API functions in `src/api/<resource>.ts`
- Pages in `src/pages/<Name>/index.tsx`, route added in `App.tsx`
- Tailwind CSS only — no new component libraries without discussion

### General

- No commented-out code
- No `fmt.Println` in production paths — use `zap` logger
- Tests are welcome and encouraged

## Development environment

| Service | URL |
|---|---|
| Frontend | http://localhost:3000 |
| Backend API | http://localhost:8080 |
| PostgreSQL | localhost:5432 |
| Redis | localhost:6379 |

Quick local login (no OAuth needed):
```env
DEV_AUTH_ENABLED=true
VITE_DEV_AUTH_ENABLED=true
```

## Questions

Open a [Discussion](https://github.com/purplehatlabs/Baldr/discussions) for anything that doesn't fit a bug report or feature request.

## License

By contributing, you agree that your contributions will be licensed under the [AGPL-3.0](LICENSE).
