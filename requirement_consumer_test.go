package rbac_test

import (
	"context"
	"errors"
	"testing"

	rbac "github.com/plutoframework/pluto-rbac"
)

// reviewOperation receives caller facts from trusted entry wiring, not a request
// body. Its mutation is private; the public entry has no permission parameter.
type reviewOperation struct {
	required *rbac.Requirement
	writes   int
}

type verifiedCaller struct {
	subject string
	scope   rbac.Scope
}

func (o *reviewOperation) execute(
	ctx context.Context,
	caller verifiedCaller,
	resourceTenant string,
) error {
	return o.required.Execute(
		ctx,
		caller.subject,
		caller.scope,
		func(context.Context) error {
			if resourceTenant != caller.scope.TenantID {
				return rbac.ErrForbidden
			}

			o.writes++

			return nil
		},
	)
}

func TestRequiredOperationConsumer(t *testing.T) {
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

	required, err := newAuthorizer(t, resolver, true).Require(manage)
	if err != nil {
		t.Fatal(err)
	}

	operation := reviewOperation{required: required}
	for _, test := range []struct {
		caller verifiedCaller
		tenant string
		want   error
	}{
		{verifiedCaller{"alice", rbac.Scope{TenantID: "north"}}, "north", nil},
		{verifiedCaller{"bob", rbac.Scope{TenantID: "north"}}, "north", rbac.ErrForbidden},
		{verifiedCaller{"alice", rbac.Scope{TenantID: "south"}}, "south", rbac.ErrForbidden},
		{verifiedCaller{"alice", rbac.Scope{TenantID: "north"}}, "south", rbac.ErrForbidden},
		{verifiedCaller{}, "north", rbac.ErrUnauthenticated},
	} {
		if err := operation.execute(
			context.Background(),
			test.caller,
			test.tenant,
		); !errors.Is(
			err,
			test.want,
		) {
			t.Fatalf("execute=%v want=%v", err, test.want)
		}
	}

	if operation.writes != 1 {
		t.Fatalf("writes=%d", operation.writes)
	}
}
