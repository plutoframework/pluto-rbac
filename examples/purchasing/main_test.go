package main

import (
	"context"
	"errors"
	"testing"

	rbac "github.com/plutoframework/pluto-rbac"
)

func TestReviewCombinesCapabilityMembershipAndOwnership(t *testing.T) {
	policy, err := rbac.New(rbac.Definition{
		Permissions: []rbac.Permission{
			{
				ID:          review,
				Name:        "Review",
				Description: "Review colleague purchases.",
			},
		},
		Roles: []rbac.Role{
			{
				ID:          "reviewer",
				Name:        "Reviewer",
				Description: "Review in the assigned scope.",
				Permissions: []rbac.PermissionID{review},
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	resolver, err := rbac.NewStaticResolver([]rbac.Assignment{
		{
			SubjectID: "bob",
			Scope:     rbac.Scope{TenantID: "north"},
			Roles:     []rbac.RoleID{"reviewer"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	authorizer, err := rbac.NewAuthorizer(
		policy,
		resolver,
		rbac.Options{RequireTenant: true},
	)
	if err != nil {
		t.Fatal(err)
	}

	for _, check := range []struct {
		name, subject, tenant string
		resource              purchase
		allowed               bool
	}{
		{"colleague", "bob", "north", purchase{TenantID: "north", CreatorID: "alice"}, true},
		{"self", "bob", "north", purchase{TenantID: "north", CreatorID: "bob"}, false},
		{"resource tenant", "bob", "north", purchase{TenantID: "harbor", CreatorID: "alice"}, false},
		{"assignment tenant", "bob", "harbor", purchase{TenantID: "harbor", CreatorID: "alice"}, false},
		{"no assignment", "carol", "north", purchase{TenantID: "north", CreatorID: "alice"}, false},
	} {
		t.Run(check.name, func(t *testing.T) {
			err := authorizeReview(
				context.Background(),
				authorizer,
				check.subject,
				rbac.Scope{TenantID: check.tenant},
				check.resource,
			)
			if check.allowed && err != nil {
				t.Fatalf("allowed operation: %v", err)
			}

			if !check.allowed && !errors.Is(err, rbac.ErrForbidden) {
				t.Fatalf("denied operation: %v", err)
			}
		})
	}
}
