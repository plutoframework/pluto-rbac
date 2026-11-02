package rbac_test

import (
	"context"
	"errors"
	"testing"

	rbac "github.com/plutoframework/pluto-rbac"
)

func TestRequirementExecution(t *testing.T) {
	failure := errors.New("resolver failed")

	callbackFailure := errors.New("write failed")
	for _, test := range []struct {
		name         string
		subject      string
		tenant       string
		roles        []rbac.RoleID
		resolveError error
		cancel       bool
		want         error
	}{
		{
			"allowed",
			"alice",
			"north",
			[]rbac.RoleID{
				admin,
			},
			nil,
			false,
			callbackFailure,
		},
		{"other subject", "bob", "north", nil, nil, false, rbac.ErrForbidden},
		{"other scope", "alice", "south", nil, nil, false, rbac.ErrForbidden},
		{"missing scope", "alice", "", nil, nil, false, rbac.ErrInvalidRequest},
		{
			"unknown role",
			"alice",
			"north",
			[]rbac.RoleID{
				admin,
				"deleted",
			},
			nil,
			false,
			rbac.ErrForbidden,
		},
		{
			"wrong permission grant",
			"alice",
			"north",
			[]rbac.RoleID{
				reader,
			},
			nil,
			false,
			rbac.ErrForbidden,
		},
		{
			"resolver error",
			"alice",
			"north",
			[]rbac.RoleID{
				admin,
			},
			failure,
			false,
			rbac.ErrResolveRoles,
		},
		{
			"cancellation",
			"alice",
			"north",
			[]rbac.RoleID{
				admin,
			},
			nil,
			true,
			context.Canceled,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			resolver := rbac.RoleResolverFunc(
				func(
					_ context.Context,
					subject string,
					scope rbac.Scope,
				) ([]rbac.RoleID, error) {
					if subject != test.subject ||
						scope.TenantID != test.tenant {
						t.Fatal("resolution key changed")
					}

					if test.cancel {
						cancel()
					}

					return test.roles, test.resolveError
				},
			)

			required, err := newAuthorizer(t, resolver, true).Require(manage)
			if err != nil {
				t.Fatal(err)
			}

			called := false

			err = required.Execute(
				ctx,
				test.subject,
				rbac.Scope{TenantID: test.tenant},
				func(got context.Context) error {
					called = true

					if got != ctx {
						t.Fatal("context changed")
					}

					return callbackFailure
				},
			)
			if !errors.Is(err, test.want) ||
				called != (test.want == callbackFailure) {
				t.Fatalf("Execute=%v, called=%v", err, called)
			}
		})
	}
}

func TestRequirementResolvesEveryExecution(t *testing.T) {
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

	writes := 0

	run := func(context.Context) error { writes++; return nil }
	if err := required.Execute(
		context.Background(),
		"alice",
		rbac.Scope{},
		run,
	); err != nil {
		t.Fatal(err)
	}

	roles = []rbac.RoleID{reader}

	if err := required.Execute(
		context.Background(),
		"alice",
		rbac.Scope{},
		run,
	); !errors.Is(
		err,
		rbac.ErrForbidden,
	) {
		t.Fatal(err)
	}

	if calls != 2 || writes != 1 {
		t.Fatalf("resolutions=%d writes=%d", calls, writes)
	}
}

func TestRequirementConfiguration(t *testing.T) {
	var (
		zero   rbac.Requirement
		absent *rbac.Requirement
	)
	for _, required := range []*rbac.Requirement{&zero, absent} {
		if err := required.Execute(
			context.Background(),
			"alice",
			rbac.Scope{},
			func(context.Context) error {
				t.Fatal("zero gate executed")

				return nil
			},
		); !errors.Is(
			err,
			rbac.ErrUnconfigured,
		) {
			t.Fatal(err)
		}
	}

	resolver, err := rbac.NewStaticResolver(nil)
	if err != nil {
		t.Fatal(err)
	}

	authorizer := newAuthorizer(t, resolver, false)
	if _, err := authorizer.Require(
		"unknown",
	); !errors.Is(
		err,
		rbac.ErrForbidden,
	) {
		t.Fatal(err)
	}

	required, err := authorizer.Require(read)
	if err != nil {
		t.Fatal(err)
	}

	if err := required.Execute(
		context.Background(),
		"alice",
		rbac.Scope{},
		nil,
	); !errors.Is(
		err,
		rbac.ErrInvalidRequest,
	) {
		t.Fatal(err)
	}

	var zeroAuthorizer rbac.Authorizer
	if _, err := zeroAuthorizer.Require(
		read,
	); !errors.Is(
		err,
		rbac.ErrUnconfigured,
	) {
		t.Fatal(err)
	}
}
