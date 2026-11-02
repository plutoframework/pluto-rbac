package rbac_test

import (
	"context"
	"errors"
	"testing"

	rbac "github.com/plutoframework/pluto-rbac"
)

func TestExecutionBindingsAndLifetime(t *testing.T) {
	resolver := rbac.RoleResolverFunc(
		func(context.Context, string, rbac.Scope) ([]rbac.RoleID, error) {
			return []rbac.RoleID{admin}, nil
		},
	)
	authorizer := newAuthorizer(t, resolver, true)

	required, err := authorizer.Require(manage)
	if err != nil {
		t.Fatal(err)
	}

	other, err := authorizer.Require(read)
	if err != nil {
		t.Fatal(err)
	}

	scope := rbac.Scope{TenantID: "north"}

	var (
		retained *rbac.Execution
		copied   rbac.Execution
	)

	err = required.Within(
		context.Background(),
		"alice",
		scope,
		"purchase:1",
		func(ctx context.Context, execution *rbac.Execution) error {
			retained = execution

			copied = *execution
			for _, test := range []struct {
				gate      *rbac.Requirement
				execution *rbac.Execution
				subject   string
				scope     rbac.Scope
				resource  string
				want      error
			}{
				{required, execution, "alice", scope, "purchase:1", nil},
				{required, &copied, "alice", scope, "purchase:1", nil},
				{
					other,
					execution,
					"alice",
					scope,
					"purchase:1",
					rbac.ErrForbidden,
				},
				{
					required,
					execution,
					"bob",
					scope,
					"purchase:1",
					rbac.ErrForbidden,
				},
				{
					required,
					execution,
					"alice",
					rbac.Scope{
						TenantID: "south",
					},
					"purchase:1",
					rbac.ErrForbidden,
				},
				{
					required,
					execution,
					"alice",
					scope,
					"purchase:2",
					rbac.ErrForbidden,
				},
				{
					required,
					&rbac.Execution{},
					"alice",
					scope,
					"purchase:1",
					rbac.ErrForbidden,
				},
				{
					required,
					nil,
					"alice",
					scope,
					"purchase:1",
					rbac.ErrForbidden,
				},
			} {
				if err := test.gate.Use(
					ctx,
					test.execution,
					test.subject,
					test.scope,
					test.resource,
					func(context.Context) error { return nil },
				); !errors.Is(
					err,
					test.want,
				) {
					t.Fatalf("Use=%v want=%v", err, test.want)
				}
			}

			return nil
		},
	)
	if err != nil {
		t.Fatal(err)
	}

	for _, execution := range []*rbac.Execution{retained, &copied} {
		if err := required.Use(
			context.Background(),
			execution,
			"alice",
			scope,
			"purchase:1",
			func(context.Context) error { return nil },
		); !errors.Is(
			err,
			rbac.ErrForbidden,
		) {
			t.Fatalf("retained execution=%v", err)
		}
	}
}

func TestExecutionRevalidatesAndCancels(t *testing.T) {
	roles := []rbac.RoleID{admin}
	calls := 0
	resolver := rbac.RoleResolverFunc(
		func(context.Context, string, rbac.Scope) ([]rbac.RoleID, error) {
			calls++
			return roles, nil
		},
	)

	required, err := newAuthorizer(t, resolver, false).Require(manage)
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	err = required.Within(
		ctx,
		"alice",
		rbac.Scope{},
		"record:1",
		func(ctx context.Context, execution *rbac.Execution) error {
			if err := required.Use(
				ctx,
				execution,
				"alice",
				rbac.Scope{},
				"record:1",
				func(context.Context) error { return nil },
			); err != nil {
				t.Fatal(err)
			}

			roles = []rbac.RoleID{reader}

			if err := required.Use(
				ctx,
				execution,
				"alice",
				rbac.Scope{},
				"record:1",
				func(context.Context) error { return nil },
			); !errors.Is(
				err,
				rbac.ErrForbidden,
			) {
				t.Fatalf("revoked=%v", err)
			}

			roles = []rbac.RoleID{admin}

			cancel()

			if err := required.Use(
				context.Background(),
				execution,
				"alice",
				rbac.Scope{},
				"record:1",
				func(context.Context) error { return nil },
			); !errors.Is(
				err,
				context.Canceled,
			) {
				t.Fatalf("replaced context=%v", err)
			}

			return nil
		},
	)
	if err != nil || calls != 3 {
		t.Fatalf("Within=%v resolutions=%d", err, calls)
	}
}

func TestExecutionInvalidAndPanic(t *testing.T) {
	resolver := rbac.RoleResolverFunc(
		func(context.Context, string, rbac.Scope) ([]rbac.RoleID, error) {
			return []rbac.RoleID{admin}, nil
		},
	)

	required, err := newAuthorizer(t, resolver, false).Require(manage)
	if err != nil {
		t.Fatal(err)
	}

	if err := required.Within(
		context.Background(),
		"alice",
		rbac.Scope{},
		"",
		func(context.Context, *rbac.Execution) error {
			t.Fatal("invalid resource executed")

			return nil
		},
	); !errors.Is(
		err,
		rbac.ErrInvalidRequest,
	) {
		t.Fatal(err)
	}

	if err := required.Within(
		context.Background(),
		"alice",
		rbac.Scope{},
		"record:1",
		nil,
	); !errors.Is(
		err,
		rbac.ErrInvalidRequest,
	) {
		t.Fatal(err)
	}

	var retained *rbac.Execution

	func() {
		defer func() {
			if recover() == nil {
				t.Fatal("missing panic")
			}
		}()

		_ = required.Within(
			context.Background(),
			"alice",
			rbac.Scope{},
			"record:1",
			func(_ context.Context, execution *rbac.Execution) error {
				retained = execution

				return required.Use(
					context.Background(),
					execution,
					"alice",
					rbac.Scope{},
					"record:1",
					func(context.Context) error { panic("callback panic") },
				)
			},
		)
	}()

	if err := required.Use(
		context.Background(),
		retained,
		"alice",
		rbac.Scope{},
		"record:1",
		func(context.Context) error { return nil },
	); !errors.Is(
		err,
		rbac.ErrForbidden,
	) {
		t.Fatal(err)
	}
}
