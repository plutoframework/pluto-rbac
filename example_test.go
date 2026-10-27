package rbac_test

import (
	"context"
	"errors"
	"fmt"

	rbac "github.com/plutoframework/pluto-rbac"
)

func ExamplePolicy() {
	policy, err := rbac.New(rbac.Definition{
		Permissions: []rbac.Permission{
			{
				ID:          "reports:read",
				Name:        "Read reports",
				Description: "Read reports allowed by resource policy.",
			},
		},
		Roles: []rbac.Role{
			{
				ID:          "analyst",
				Name:        "Analyst",
				Description: "Inspect reports.",
				Permissions: []rbac.PermissionID{"reports:read"},
			},
		},
	})
	if err != nil {
		panic(err)
	}

	fmt.Println(policy.Allows([]rbac.RoleID{"analyst"}, "reports:read"))
	fmt.Println(policy.Allows([]rbac.RoleID{"analyst"}, "reports:delete"))

	// Output:
	// true
	// false
}

func ExampleAuthorizer() {
	policy, err := rbac.New(definition())
	if err != nil {
		panic(err)
	}

	resolver, err := rbac.NewStaticResolver([]rbac.Assignment{
		{
			SubjectID: "alice",
			Scope:     rbac.Scope{TenantID: "north"},
			Roles:     []rbac.RoleID{reviewer},
		},
	})
	if err != nil {
		panic(err)
	}

	authorizer, err := rbac.NewAuthorizer(
		policy,
		resolver,
		rbac.Options{RequireTenant: true},
	)
	if err != nil {
		panic(err)
	}

	request := rbac.Request{
		SubjectID:  "alice",
		Scope:      rbac.Scope{TenantID: "north"},
		Permission: approve,
	}
	fmt.Println(authorizer.Authorize(context.Background(), request) == nil)

	request.Scope.TenantID = "harbor"
	fmt.Println(errors.Is(
		authorizer.Authorize(context.Background(), request),
		rbac.ErrForbidden,
	))

	// Output:
	// true
	// true
}
