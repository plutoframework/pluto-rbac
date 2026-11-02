package rbac_test

import (
	"context"
	"errors"
	"testing"

	rbac "github.com/plutoframework/pluto-rbac"
)

func TestRequiredResourcePolicy(t *testing.T) {
	resolver := rbac.RoleResolverFunc(
		func(context.Context, string, rbac.Scope) ([]rbac.RoleID, error) {
			return []rbac.RoleID{admin}, nil
		},
	)

	base, err := newAuthorizer(t, resolver, true).Require(manage)
	if err != nil {
		t.Fatal(err)
	}

	allowed := true
	evaluations := 0

	resource, err := base.WithResourcePolicy(
		rbac.ResourcePolicyFunc(
			func(_ context.Context, request rbac.Request, key string) error {
				evaluations++

				if request.SubjectID != "alice" ||
					request.Scope.TenantID != "north" ||
					request.Permission != manage ||
					key != "one" {
					t.Fatal("resource policy binding changed")
				}

				if !allowed {
					return rbac.ErrForbidden
				}

				return nil
			},
		),
	)
	if err != nil {
		t.Fatal(err)
	}

	scope := rbac.Scope{TenantID: "north"}
	writes := 0

	err = resource.Within(
		context.Background(),
		"alice",
		scope,
		"one",
		func(ctx context.Context, execution *rbac.Execution) error {
			if err := base.Use(
				ctx,
				execution,
				"alice",
				scope,
				"one",
				func(context.Context) error {
					t.Fatal("permission gate bypassed resource policy")

					return nil
				},
			); !errors.Is(
				err,
				rbac.ErrForbidden,
			) {
				t.Fatal(err)
			}

			if err := resource.Use(
				ctx,
				execution,
				"alice",
				scope,
				"one",
				func(context.Context) error { writes++; return nil },
			); err != nil {
				t.Fatal(err)
			}

			allowed = false

			return resource.Use(
				ctx,
				execution,
				"alice",
				scope,
				"one",
				func(context.Context) error {
					t.Fatal("changed resource policy bypassed")

					return nil
				},
			)
		},
	)
	if !errors.Is(err, rbac.ErrForbidden) || writes != 1 || evaluations != 3 {
		t.Fatalf("err=%v writes=%d evaluations=%d", err, writes, evaluations)
	}

	if err := resource.Within(
		context.Background(),
		"alice",
		scope,
		"one",
		func(context.Context, *rbac.Execution) error {
			t.Fatal("denied resource entered")

			return nil
		},
	); !errors.Is(
		err,
		rbac.ErrForbidden,
	) {
		t.Fatal(err)
	}
}
