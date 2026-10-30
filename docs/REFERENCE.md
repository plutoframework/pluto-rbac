# Pluto RBAC

A small Go authorization library with **zero third-party dependencies**.
Define named roles and capabilities once, compile an immutable policy, and check
trusted role assignments directly or resolve them for an authenticated subject.

This is an initial standalone implementation for Pluto, using the module
`github.com/plutoframework/pluto-rbac`. Go 1.25.5+ is required. Build and try the application example locally:

```sh
go test ./...
go run ./examples/purchasing
go doc .
```

## Declare the catalog

Stable IDs are authorization contracts. Names and descriptions support role
assignment UIs and documentation; they never determine a grant. Permission IDs
are independent of endpoint names, URLs and feature flags.

```go
const ReadReports rbac.PermissionID = "reports:read"
const Analyst rbac.RoleID = "analyst"

policy, err := rbac.New(rbac.Definition{
    Permissions: []rbac.Permission{
        {
            ID:          ReadReports,
            Name:        "Read reports",
            Description: "Read reports allowed by resource policy.",
        },
    },
    Roles: []rbac.Role{
        {
            ID:          Analyst,
            Name:        "Analyst",
            Description: "Inspect reports in the active scope.",
            Permissions: []rbac.PermissionID{ReadReports},
        },
    },
})
if err != nil {
    return err
}

allowed := policy.Allows([]rbac.RoleID{Analyst}, ReadReports)
```

Call `Allows` only with trusted role IDs, such as roles from a verified principal
or a server-side membership lookup. The function evaluates grants; it cannot
authenticate a user or prove that a role belongs to them.

Multiple assigned roles contribute a union of permissions. `Role.Inherits`
names other roles whose permissions are included, transitively. An administrator
has exactly its declared/inherited permissions: its name grants no special power.
Duplicate IDs/grants/parents, unknown grants/parents and inheritance cycles fail
construction with `ErrInvalidPolicy`. Empty catalogs and grantless roles are valid
and grant nothing. There are no wildcards, pattern matching or explicit deny
rules. IDs use lowercase letters/digits with single `.`, `_`, `:` or `-`
separators; they start with a letter and end with a letter or digit. Display text
must be nonempty, trimmed valid UTF-8 without control characters.

An unknown permission denies. **Any unknown assigned role invalidates the whole
assignment**, including a mix of valid and unknown roles, so a stale catalog or
assignment cannot accidentally retain part of a privileged grant. A role with no
grants contributes nothing and does not negate grants from other known roles.
Matching is exact and case-sensitive; input is never silently normalized.

`policy.Roles()`, `policy.Permissions()` and `policy.EffectivePermissions(role)`
return defensive copies sorted by ID. Roles retain direct grants/inheritance in
declaration order. Effective permissions include transitive grants with no
duplicates. Catalog enumeration is for a trusted application: deciding who may
see or assign roles remains its authorization responsibility.

## Resolve roles per subject and scope

For single tenancy, `Options{}` accepts only an empty scope. Multi tenancy is
explicitly enabled and requires a tenant on every request:

```go
resolver, err := rbac.NewStaticResolver([]rbac.Assignment{
    {
        SubjectID: "alice",
        Scope:     rbac.Scope{TenantID: "northstar"},
        Roles:     []rbac.RoleID{Analyst},
    },
})
if err != nil {
    return err
}

authorizer, err := rbac.NewAuthorizer(
    policy,
    resolver,
    rbac.Options{RequireTenant: true},
)
if err != nil {
    return err
}

err = authorizer.Authorize(ctx, rbac.Request{
    SubjectID:  authenticatedActorID,
    Scope:      rbac.Scope{TenantID: verifiedTenantID},
    Permission: ReadReports,
})
if err != nil {
    return err
}
```

Subject IDs come from authentication; tenant selection must be verified against
membership by the application/resolver. Supplying a nonempty ID does not verify
an identity. Never bind these fields directly from an arbitrary identity/role
header or JSON body. Subject and tenant strings are opaque, exact, nonempty
trimmed UTF-8 without control characters. A tenant is absent only in single mode.

The static resolver indexes the exact `(subject, scope)` pair. Missing subjects
or tenants yield no roles, never a global or other-tenant fallback. Duplicate
subject/scope assignments and malformed/repeated role IDs fail construction with
`ErrInvalidResolver`. Unknown well-formed role IDs are denied by the authorizer
against its policy. Static assignments are copied once; rebuild the resolver to
change that snapshot.

For database-backed membership, implement the consumer-sized interface:

```go
type RoleResolver interface {
    Roles(context.Context, string, rbac.Scope) ([]rbac.RoleID, error)
}
```

`RoleResolverFunc` adapts a function for tests or a small repository wrapper.
Resolve only the requested authenticated subject in the exact selected tenant.
A PostgreSQL query must constrain **both subject and tenant**, rather than load
roles by subject alone. Keep typed SQL/sqlc code in an application adapter. The
library has no storage driver, ORM, HTTP dependency or global assignment store.

Resolver errors deny even if roles were also returned. Underlying errors remain
available through `errors.Is`/`errors.As` and `ErrResolveRoles`; map them to an
appropriate generic response at the HTTP boundary rather than exposing database
errors. Missing identity returns `ErrUnauthenticated`, wrong/missing scope returns
`ErrInvalidRequest`, and insufficient/unknown roles or permissions return
`ErrForbidden`. Unknown permissions and invalid requests never call the resolver.
Nil or zero authorizers deny with `ErrUnconfigured`. Cancellation is checked
before and after resolution, and preserves the context error.

## Keep resource policy explicit

RBAC answers whether a subject holds a capability in a scope. It does not prove
that a fetched record belongs to that scope, allow self-approval, or bypass
ownership rules. [The purchasing example](../examples/purchasing/main.go) shows
separate checks for those conditions. A feature flag can disable a capability;
enabling it does not grant the permission. Route checks and business-operation
checks should use the same policy and verified scope.
Consumers can define a narrow `Authorize(context.Context, rbac.Request) error`
interface to inject either this authorizer or a test fake; the purchasing example
demonstrates that boundary.

Roles, permissions and resource policies follow the boundaries discussed in
[NIST's RBAC overview](https://csrc.nist.gov/Projects/Role-Based-Access-Control/faqs)
and [Casbin's domain-scoped RBAC](https://casbin.org/docs/rbac-with-domains/).
These are design references, not dependencies or a claim of standards compliance.
Session activation, separation-of-duty constraints, ABAC, automatic role
administration, caching, SQL adapters and durable audits are outside this version.

Policies and static resolvers support concurrent reads without locks. All mutable
constructor inputs and catalog/static-resolver outputs are copied. Custom
resolvers must be concurrency-safe and return immutable or caller-owned slices.
`Authorizer` has no assignment cache and resolves anew on each call. A custom
resolver's caching/freshness semantics still apply. Revocation can race a write
already authorized; use database transactions/rechecks for stronger requirements.
Publish a replacement policy/authorizer through application-owned synchronization
when reloading; do not race changes to an application pointer or input definition.
The compiler resolves inheritance iteratively, but precomputes effective grants;
large dense role graphs cost proportional memory. Policies are trusted startup
configuration, not unbounded request payloads.

## Development and verification

Tests use only Go and the standard library. The optional developer formatter is
pinned in mise.toml; scripts accept that installed version or invoke it via mise.
Review before `mise trust` and `mise install`. Python 3.11+ is needed by scripts.

```sh
./scripts/fmt.sh
./scripts/check.sh
go test -race ./...
go test -cover ./...
go test -run '^$' -fuzz '^FuzzPolicyMatchesReference$' -fuzztime=5s -parallel=2
go test -run '^$' -fuzz '^FuzzTenantIsolation$' -fuzztime=5s -parallel=2
python3 scripts/mutation-smoke.py
go test -run '^$' -bench . -benchmem ./...
```

The configurable formatter target is 80 columns (golines, gofumpt, gci and
wsl_v5). Static checks never rewrite code. Files have a hard 1,000-line ceiling.
Tests exercise exact decisions, hierarchy validation, input/output immutability,
tenant/subject isolation, errors, cancellation, role changes, concurrent reads and
executable examples. Fuzzing compares compilation to an independent traversal
oracle and checks that privileged assignments never cross tenant scopes. The
mutation smoke alters six relevant guards/ownership properties in disposable
copies; every mutant must be killed, with build failures and timeouts reported
separately. It is a bounded smoke check, not comprehensive mutation coverage.
Benchmarks report actual allocations/timing; no blanket performance claim is made.

Import `github.com/plutoframework/pluto-rbac` and install the initial release
with `go get github.com/plutoframework/pluto-rbac@v0.1.0`. Releases before v1
may change their API. To work against a sibling local checkout, add an explicit
replacement in the consuming app (or use a local Go workspace):

```sh
go mod edit -require=github.com/plutoframework/pluto-rbac@v0.0.0
go mod edit -replace=github.com/plutoframework/pluto-rbac=../pluto-rbac
go mod tidy
```

The [Pluto CLI](https://github.com/plutoframework/cli) and its generated apps, plus
the [purchasing example](https://github.com/plutoframework/pluto-example), import
this library at an explicit pinned version. Their authenticators resolve trusted
role assignments; each application compiles and injects its own role catalog.
