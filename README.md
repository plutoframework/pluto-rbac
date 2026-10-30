<p align="center">
  <img src="https://raw.githubusercontent.com/plutoframework/pluto/main/assets/readme/banner.svg" alt="Pluto — a small framework, wide open possibilities" width="100%" />
</p>

# Pluto RBAC

Named roles. Explicit permissions. Default deny.

[Website](https://plutoframework.github.io/pluto-site/) · [Documentation](https://plutoframework.github.io/pluto-site/docs/backend/rbac/) · [CLI demo](https://github.com/plutoframework/pluto/blob/main/docs/DEMO.md) · [First issues](https://github.com/plutoframework/pluto/blob/main/CONTRIBUTING.md#starter-tasks)

## What you get

- Compile an immutable policy with named, described roles and capabilities.
- Resolve trusted assignments in an explicit subject and tenant scope.
- Keep identity, resource ownership and persistence outside the policy engine.

## Get started

### 1. Install

From a Go **1.25.5+** module:

```sh
go get github.com/plutoframework/pluto-rbac@v0.1.0
```

The runtime has **zero third-party dependencies**.

### 2. Resolve assignments and authorize a real operation

This complete program declares the catalog, resolves a trusted tenant assignment
and keeps resource ownership separate from the capability grant. Save it as
`cmd/review/main.go` and run `go run ./cmd/review`, or run
`go run ./examples/purchasing` from a repository checkout.

<!-- example-source: examples/purchasing/main.go -->

```go
// Purchasing demonstrates RBAC plus separate resource and tenant policies.
package main

import (
	"context"
	"errors"
	"fmt"

	rbac "github.com/plutoframework/pluto-rbac"
)

const review rbac.PermissionID = "purchases:review"

type purchase struct {
	TenantID  string
	CreatorID string
}

// The consumer owns the interface so business logic can use a small test fake.
type permissionChecker interface {
	Authorize(context.Context, rbac.Request) error
}

func authorizeReview(
	ctx context.Context,
	authorizer permissionChecker,
	subjectID string,
	scope rbac.Scope,
	resource purchase,
) error {
	if err := authorizer.Authorize(ctx, rbac.Request{
		SubjectID:  subjectID,
		Scope:      scope,
		Permission: review,
	}); err != nil {
		return err
	}

	// A review capability never grants cross-tenant access or self-approval.
	if resource.TenantID != scope.TenantID || resource.CreatorID == subjectID {
		return rbac.ErrForbidden
	}

	return nil
}

func run() error {
	policy, err := rbac.New(rbac.Definition{
		Permissions: []rbac.Permission{
			{
				ID:          review,
				Name:        "Review purchase requests",
				Description: "Review colleagues' requests in the active organization.",
			},
		},
		Roles: []rbac.Role{
			{
				ID:          "reviewer",
				Name:        "Reviewer",
				Description: "Review organization requests.",
				Permissions: []rbac.PermissionID{review},
			},
		},
	})
	if err != nil {
		return err
	}

	resolver, err := rbac.NewStaticResolver([]rbac.Assignment{
		{
			SubjectID: "bob",
			Scope:     rbac.Scope{TenantID: "north"},
			Roles:     []rbac.RoleID{"reviewer"},
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

	for _, test := range []struct {
		name     string
		resource purchase
	}{
		{"colleague", purchase{TenantID: "north", CreatorID: "alice"}},
		{"self approval", purchase{TenantID: "north", CreatorID: "bob"}},
		{"another tenant", purchase{TenantID: "harbor", CreatorID: "alice"}},
	} {
		err := authorizeReview(
			context.Background(),
			authorizer,
			"bob", // Supplied by the application's authenticated principal.
			rbac.Scope{TenantID: "north"},
			test.resource,
		)
		if err != nil && !errors.Is(err, rbac.ErrForbidden) {
			return err
		}

		fmt.Printf("%s allowed: %v\n", test.name, err == nil)
	}

	return nil
}

func main() {
	if err := run(); err != nil {
		panic(err)
	}
}
```

<!-- /example-source -->

Expected output:

```text
colleague allowed: true
self approval allowed: false
another tenant allowed: false
```

### 3. Add policy to your operations

Build the policy once at application startup. Inject trusted role resolution and
check permissions in application operations, including calls outside HTTP. Use
`policy.Roles()` and `policy.Permissions()` for catalog metadata in an admin UI.
Never accept role grants from the browser or treat tenant selection as membership.

## Read further

- [API and integration reference](docs/REFERENCE.md)
- [Field guide](https://plutoframework.github.io/pluto-site/docs/backend/rbac/)
- [Pluto ecosystem](https://github.com/plutoframework/pluto#the-ecosystem)

## Boundaries

Unknown roles invalidate the entire assignment. Policies do not authenticate users or decide resource ownership. Revocation/freshness belongs to the assignment resolver.

## Contribute

Start with [CONTRIBUTING.md](CONTRIBUTING.md), then choose a [good first issue](https://github.com/plutoframework/pluto/blob/main/CONTRIBUTING.md#starter-tasks).
