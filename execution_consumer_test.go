package rbac_test

import (
	"context"
	"errors"
	"testing"

	rbac "github.com/plutoframework/pluto-rbac"
)

// The consumer-owned write port requires an execution, not a boolean grant.
type restrictedPurchaseWriter interface {
	write(context.Context, *rbac.Execution, string, rbac.Scope, string) error
}

type guardedPurchaseStore struct {
	requirement *rbac.Requirement
	writes      int
	calls       int
}

func (s *guardedPurchaseStore) write(
	ctx context.Context,
	execution *rbac.Execution,
	subject string,
	scope rbac.Scope,
	id string,
) error {
	s.calls++

	return s.requirement.Use(
		ctx,
		execution,
		subject,
		scope,
		id,
		func(context.Context) error {
			s.writes++
			return nil
		},
	)
}

type gatedPurchaseOperation struct {
	requirement *rbac.Requirement
	writer      restrictedPurchaseWriter
}

func (o *gatedPurchaseOperation) execute(
	ctx context.Context,
	caller verifiedCaller,
	id string,
) error {
	return o.requirement.Within(
		ctx,
		caller.subject,
		caller.scope,
		id,
		func(ctx context.Context, execution *rbac.Execution) error {
			return o.writer.write(
				ctx,
				execution,
				caller.subject,
				caller.scope,
				id,
			)
		},
	)
}

func TestRestrictedWriteConsumer(t *testing.T) {
	roles := []rbac.RoleID{admin}
	resolver := rbac.RoleResolverFunc(
		func(context.Context, string, rbac.Scope) ([]rbac.RoleID, error) {
			return roles, nil
		},
	)

	requirement, err := newAuthorizer(t, resolver, true).Require(manage)
	if err != nil {
		t.Fatal(err)
	}

	store := &guardedPurchaseStore{requirement: requirement}
	operation := gatedPurchaseOperation{requirement: requirement, writer: store}

	caller := verifiedCaller{"alice", rbac.Scope{TenantID: "north"}}
	if err := store.write(
		context.Background(),
		&rbac.Execution{},
		caller.subject,
		caller.scope,
		"purchase:1",
	); !errors.Is(
		err,
		rbac.ErrForbidden,
	) {
		t.Fatalf("direct write=%v", err)
	}

	roles = []rbac.RoleID{reader}
	calls := store.calls

	if err := operation.execute(
		context.Background(),
		caller,
		"purchase:1",
	); !errors.Is(
		err,
		rbac.ErrForbidden,
	) {
		t.Fatalf("denied operation=%v", err)
	}

	if store.calls != calls {
		t.Fatal("denied operation reached write adapter")
	}

	roles = []rbac.RoleID{admin}

	if err := operation.execute(
		context.Background(),
		caller,
		"purchase:1",
	); err != nil {
		t.Fatal(err)
	}

	var retained *rbac.Execution

	err = requirement.Within(
		context.Background(),
		caller.subject,
		caller.scope,
		"purchase:1",
		func(ctx context.Context, execution *rbac.Execution) error {
			retained = execution
			if err := store.write(
				ctx,
				execution,
				caller.subject,
				rbac.Scope{TenantID: "south"},
				"purchase:1",
			); !errors.Is(
				err,
				rbac.ErrForbidden,
			) {
				t.Fatalf("cross-scope write=%v", err)
			}

			roles = []rbac.RoleID{reader}

			return store.write(
				ctx,
				execution,
				caller.subject,
				caller.scope,
				"purchase:1",
			)
		},
	)
	if !errors.Is(err, rbac.ErrForbidden) {
		t.Fatalf("revoked write=%v", err)
	}

	if err := store.write(
		context.Background(),
		retained,
		caller.subject,
		caller.scope,
		"purchase:1",
	); !errors.Is(
		err,
		rbac.ErrForbidden,
	) {
		t.Fatalf("replayed write=%v", err)
	}

	if store.writes != 1 {
		t.Fatalf("writes=%d", store.writes)
	}
}
