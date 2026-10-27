# Working on Pluto RBAC

This is a standalone authorization library. Only modify this repository for
routine library work. Sibling Pluto projects are design references.

- Keep the runtime and Go tests standard-library-only. The module path is
  github.com/plutoframework/pluto-rbac. Publishing requires task authorization.
- Preserve exact grants, deny-by-default behavior, and subject/scope separation.
  Never introduce wildcard roles, automatic administrators or tenant fallbacks.
- Keep HTTP/authentication, resource ownership, SQL/persistence, feature flags,
  logging destinations and assignment management outside the core.
- Public policies/resolvers are immutable snapshots. Copy mutable inputs and
  catalog outputs. Custom resolvers must document concurrency/freshness behavior.
- Return errors for invalid policies. Reject unknown parents/grants and cycles.
  Unknown roles invalidate an entire request, even with known privileged roles.
- Use explicit injection and consumer-owned interfaces. Keep files below 1,000
  lines and use the configurable 80-column formatter target, expanded literals
  and readable spacing. Never compress source to satisfy file limits.
- Run scripts/fmt.sh, scripts/check.sh and go test -race ./... after changes.
  For authorization changes run both bounded fuzz commands and the mutation smoke
  documented in README. Mutation build failures/timeouts are not killed mutants.
- Benchmark before making performance claims. Do not hide revocation/cancellation
  or concurrency tradeoffs behind a cache or an implicit policy reload.
- Do not commit, push, initialize remotes or change sibling examples/CLI without
  task authorization. Avoid tests that require databases or external services.
