package rbac_test

import (
	"context"
	"errors"
	"sync"
	"testing"

	rbac "github.com/plutoframework/pluto-rbac"
)

func newAuthorizer(
	t testing.TB,
	resolver rbac.RoleResolver,
	multi bool,
) *rbac.Authorizer {
	t.Helper()

	authorizer, err := rbac.NewAuthorizer(
		newPolicy(t),
		resolver,
		rbac.Options{RequireTenant: multi},
	)
	if err != nil {
		t.Fatal(err)
	}

	return authorizer
}

func TestTenantIsolation(t *testing.T) {
	resolver, err := rbac.NewStaticResolver([]rbac.Assignment{
		{
			SubjectID: "alice",
			Scope:     rbac.Scope{TenantID: "north"},
			Roles:     []rbac.RoleID{admin},
		},
		{
			SubjectID: "alice",
			Scope:     rbac.Scope{TenantID: "harbor"},
			Roles:     []rbac.RoleID{reader},
		},
		{SubjectID: "alice", Roles: []rbac.RoleID{admin}},
		{
			SubjectID: "bob",
			Scope:     rbac.Scope{TenantID: "harbor"},
			Roles:     []rbac.RoleID{admin},
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	authorizer := newAuthorizer(t, resolver, true)

	for _, test := range []struct {
		subject, tenant string
		permission      rbac.PermissionID
		want            error
	}{
		{"alice", "north", manage, nil},
		{"alice", "harbor", read, nil},
		{"alice", "harbor", manage, rbac.ErrForbidden},
		{"alice", "unknown", read, rbac.ErrForbidden},
		{"missing", "north", read, rbac.ErrForbidden},
		{"bob", "harbor", manage, nil},
		{"bob", "north", read, rbac.ErrForbidden},
		{"alice", "", read, rbac.ErrInvalidRequest},
		{"alice", " north", read, rbac.ErrInvalidRequest},
		{"", "north", read, rbac.ErrUnauthenticated},
		{"alice\n", "north", read, rbac.ErrUnauthenticated},
		{"alice", "north", "unknown", rbac.ErrForbidden},
	} {
		request := rbac.Request{
			SubjectID:  test.subject,
			Scope:      rbac.Scope{TenantID: test.tenant},
			Permission: test.permission,
		}

		err := authorizer.Authorize(context.Background(), request)
		if !errors.Is(err, test.want) {
			t.Errorf("Authorize(%+v)=%v, want %v", request, err, test.want)
		}
	}
}

func TestSingleTenancy(t *testing.T) {
	calls := 0
	resolver := rbac.RoleResolverFunc(func(
		_ context.Context,
		subject string,
		scope rbac.Scope,
	) ([]rbac.RoleID, error) {
		calls++

		if subject != "alice" || scope != (rbac.Scope{}) {
			t.Fatal("unexpected resolution key")
		}

		return []rbac.RoleID{reader}, nil
	})
	authorizer := newAuthorizer(t, resolver, false)

	request := rbac.Request{SubjectID: "alice", Permission: read}
	if err := authorizer.Authorize(context.Background(), request); err != nil {
		t.Fatal(err)
	}

	request.Scope.TenantID = "north"
	if err := authorizer.Authorize(
		context.Background(),
		request,
	); !errors.Is(
		err,
		rbac.ErrInvalidRequest,
	) {
		t.Fatalf("single-tenancy accepted tenant: %v", err)
	}

	if calls != 1 {
		t.Fatalf("invalid request reached resolver: calls=%d", calls)
	}
}

func TestResolverFailures(t *testing.T) {
	databaseError := errors.New("database unavailable")
	for _, test := range []struct {
		name  string
		roles []rbac.RoleID
		err   error
		want  error
	}{
		{"missing", nil, nil, rbac.ErrForbidden},
		{"unknown", []rbac.RoleID{admin, "deleted"}, nil, rbac.ErrForbidden},
		{"error with privileged roles", []rbac.RoleID{admin}, databaseError, rbac.ErrResolveRoles},
	} {
		t.Run(test.name, func(t *testing.T) {
			resolver := rbac.RoleResolverFunc(
				func(context.Context, string, rbac.Scope) ([]rbac.RoleID, error) {
					return test.roles, test.err
				},
			)

			err := newAuthorizer(t, resolver, false).Authorize(
				context.Background(),
				rbac.Request{SubjectID: "alice", Permission: read},
			)
			if !errors.Is(err, test.want) ||
				test.err != nil && !errors.Is(err, test.err) {
				t.Fatalf("resolution error=%v, want %v", err, test.want)
			}
		})
	}
}

func TestCancellationAndValidation(t *testing.T) {
	calls := 0
	ctx, cancel := context.WithCancel(context.Background())
	resolver := rbac.RoleResolverFunc(
		func(context.Context, string, rbac.Scope) ([]rbac.RoleID, error) {
			calls++

			cancel()

			return []rbac.RoleID{admin}, nil
		},
	)
	authorizer := newAuthorizer(t, resolver, false)
	request := rbac.Request{SubjectID: "alice", Permission: read}

	//nolint:staticcheck // Intentionally exercise the nil-context rejection contract.
	if err := authorizer.Authorize(
		nil,
		request,
	); !errors.Is(
		err,
		rbac.ErrInvalidRequest,
	) {
		t.Fatalf("nil context=%v", err)
	}

	unknown := request

	unknown.Permission = "unknown"
	if err := authorizer.Authorize(
		ctx,
		unknown,
	); !errors.Is(
		err,
		rbac.ErrForbidden,
	) {
		t.Fatalf("unknown permission=%v", err)
	}

	if calls != 0 {
		t.Fatal("invalid request reached resolver")
	}

	if err := authorizer.Authorize(
		ctx,
		request,
	); !errors.Is(
		err,
		context.Canceled,
	) {
		t.Fatalf("cancelled during resolution=%v", err)
	}

	if err := authorizer.Authorize(
		ctx,
		request,
	); !errors.Is(err, context.Canceled) ||
		calls != 1 {
		t.Fatalf(
			"cancelled request reached resolver: err=%v calls=%d",
			err,
			calls,
		)
	}
}

func TestNoAssignmentCache(t *testing.T) {
	roles := []rbac.RoleID{admin}
	resolver := rbac.RoleResolverFunc(
		func(context.Context, string, rbac.Scope) ([]rbac.RoleID, error) {
			return roles, nil
		},
	)
	authorizer := newAuthorizer(t, resolver, false)

	request := rbac.Request{SubjectID: "alice", Permission: manage}
	if err := authorizer.Authorize(context.Background(), request); err != nil {
		t.Fatal(err)
	}

	roles = []rbac.RoleID{reader}

	if err := authorizer.Authorize(
		context.Background(),
		request,
	); !errors.Is(
		err,
		rbac.ErrForbidden,
	) {
		t.Fatalf("revoked assignment retained: %v", err)
	}
}

func TestAuthorizerConfiguration(t *testing.T) {
	policy := newPolicy(t)

	var (
		nilFunction rbac.RoleResolverFunc
		nilPointer  *rbac.StaticResolver
	)

	for _, resolver := range []rbac.RoleResolver{nil, nilFunction, nilPointer} {
		if _, err := rbac.NewAuthorizer(
			policy,
			resolver,
			rbac.Options{},
		); !errors.Is(
			err,
			rbac.ErrInvalidResolver,
		) {
			t.Fatalf("nil resolver error=%v", err)
		}
	}

	resolver, err := rbac.NewStaticResolver(nil)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := rbac.NewAuthorizer(
		nil,
		resolver,
		rbac.Options{},
	); !errors.Is(
		err,
		rbac.ErrUnconfigured,
	) {
		t.Fatalf("nil policy error=%v", err)
	}

	var (
		absent *rbac.Authorizer
		zero   rbac.Authorizer
	)

	for _, authorizer := range []*rbac.Authorizer{absent, &zero} {
		if err := authorizer.Authorize(
			context.Background(),
			rbac.Request{},
		); !errors.Is(
			err,
			rbac.ErrUnconfigured,
		) {
			t.Fatalf("zero authorizer=%v", err)
		}
	}

	if _, err := nilFunction.Roles(
		context.Background(),
		"alice",
		rbac.Scope{},
	); !errors.Is(
		err,
		rbac.ErrInvalidResolver,
	) {
		t.Fatalf("nil function adapter=%v", err)
	}
}

func TestConcurrentAuthorization(t *testing.T) {
	resolver, err := rbac.NewStaticResolver([]rbac.Assignment{
		{
			SubjectID: "alice",
			Scope:     rbac.Scope{TenantID: "north"},
			Roles:     []rbac.RoleID{admin},
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	authorizer := newAuthorizer(t, resolver, true)

	var workers sync.WaitGroup

	for range 16 {
		workers.Go(func() {
			for range 100 {
				if err := authorizer.Authorize(
					context.Background(),
					rbac.Request{
						SubjectID:  "alice",
						Scope:      rbac.Scope{TenantID: "north"},
						Permission: read,
					},
				); err != nil {
					t.Error(err)
				}
			}
		})
	}

	workers.Wait()
}
