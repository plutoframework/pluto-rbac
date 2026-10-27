package rbac_test

import (
	"context"
	"errors"
	"testing"

	rbac "github.com/plutoframework/pluto-rbac"
)

func TestStaticResolverCopies(t *testing.T) {
	input := []rbac.Assignment{
		{SubjectID: "alice", Roles: []rbac.RoleID{reader}},
	}

	resolver, err := rbac.NewStaticResolver(input)
	if err != nil {
		t.Fatal(err)
	}

	input[0].Roles[0] = admin
	input[0].SubjectID = "bob"

	roles, err := resolver.Roles(context.Background(), "alice", rbac.Scope{})
	if err != nil || len(roles) != 1 || roles[0] != reader {
		t.Fatalf("input mutation reached resolver: %v %v", roles, err)
	}

	roles[0] = admin

	roles, err = resolver.Roles(context.Background(), "alice", rbac.Scope{})
	if err != nil || len(roles) != 1 || roles[0] != reader {
		t.Fatalf("output mutation reached resolver: %v %v", roles, err)
	}

	roles, err = resolver.Roles(context.Background(), "bob", rbac.Scope{})
	if err != nil || len(roles) != 0 {
		t.Fatalf("missing subject=%v %v", roles, err)
	}
}

func TestStaticResolverValidation(t *testing.T) {
	for _, assignments := range [][]rbac.Assignment{
		{{SubjectID: ""}},
		{{SubjectID: " alice"}},
		{{SubjectID: "alice", Scope: rbac.Scope{TenantID: "\x00"}}},
		{{SubjectID: "alice"}, {SubjectID: "alice"}},
		{{SubjectID: "alice", Roles: []rbac.RoleID{reader, reader}}},
		{{SubjectID: "alice", Roles: []rbac.RoleID{"*"}}},
	} {
		if _, err := rbac.NewStaticResolver(
			assignments,
		); !errors.Is(
			err,
			rbac.ErrInvalidResolver,
		) {
			t.Fatalf("invalid assignments accepted: %v", err)
		}
	}

	var resolver rbac.StaticResolver

	roles, err := resolver.Roles(context.Background(), "alice", rbac.Scope{})
	if err != nil || len(roles) != 0 {
		t.Fatalf("zero resolver=%v %v", roles, err)
	}

	//nolint:staticcheck // Intentionally exercise the nil-context rejection contract.
	if _, err := resolver.Roles(
		nil,
		"alice",
		rbac.Scope{},
	); !errors.Is(
		err,
		rbac.ErrInvalidRequest,
	) {
		t.Fatalf("nil context=%v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if _, err := resolver.Roles(
		ctx,
		"alice",
		rbac.Scope{},
	); !errors.Is(
		err,
		context.Canceled,
	) {
		t.Fatalf("cancelled resolver=%v", err)
	}

	var absent *rbac.StaticResolver
	if _, err := absent.Roles(
		context.Background(),
		"alice",
		rbac.Scope{},
	); !errors.Is(
		err,
		rbac.ErrInvalidResolver,
	) {
		t.Fatalf("nil resolver=%v", err)
	}
}
