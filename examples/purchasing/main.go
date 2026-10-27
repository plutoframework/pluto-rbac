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
