# Project agent memory

This file is the project's committed home for project-intrinsic agent knowledge: build, test, release, architecture, and sharp-edge notes that should travel with the code.

- Add durable project-specific notes here as they are discovered through real work.

## Verification state

A `Verification` is terminally verified in `COMPLETED` and
`FALLBACK_COMPLETE`. Use `TERMINAL_VERIFIED_STATES` from
`api/src/lib/verificationState.ts` whenever a lookup needs verified states.

- Integration tests need a real Postgres; see the docblock atop
  `api/src/__tests__/helpers/testApp.ts` for the local docker one-liner and
  `DATABASE_URL`. Suites self-skip (`describe.skip`) when no DB is reachable.

## Maintaining this file

Keep this file for knowledge useful to almost every future agent session in this project.
Do not repeat what the codebase already shows; point to the authoritative file or command instead.
Prefer rewriting or pruning existing entries over appending new ones.
When updating this file, preserve this bar for all agents and keep entries concise.
