package identitytest_test

import (
	"context"
	"errors"
	"testing"

	rbac "github.com/plutoframework/pluto-rbac"
	identitygate "github.com/plutoframework/pluto-rbac/identity"
	"github.com/plutoframework/pluto-rbac/identity/identitytest"
)

func options() identitytest.Options {
	return identitytest.Options{
		Policy: rbac.Definition{
			Permissions: []rbac.Permission{
				{ID: "review", Name: "Review", Description: "Review"},
			},
			Roles: []rbac.Role{
				{
					ID:          "reviewer",
					Name:        "Reviewer",
					Description: "Reviews",
					Permissions: []rbac.PermissionID{"review"},
				},
				{ID: "viewer", Name: "Viewer", Description: "Views"},
			},
		},
		Permission: "review",
		Members: []identitytest.Member{
			{
				SubjectID: "alice",
				TenantID:  "north",
				Roles:     []rbac.RoleID{"reviewer"},
			},
			{
				SubjectID: "bob",
				TenantID:  "north",
				Roles:     []rbac.RoleID{"viewer"},
			},
		},
	}
}

func noop(context.Context, *identitygate.Execution) error { return nil }

func TestMintsBoundExecutionThroughRealGate(t *testing.T) {
	h, err := identitytest.New(options())
	if err != nil {
		t.Fatal(err)
	}

	used := false

	err = h.Within(
		t.Context(), "alice", "north", "doc-1",
		func(ctx context.Context, exec *identitygate.Execution) error {
			if exec.SubjectID() != "alice" || exec.TenantID() != "north" ||
				exec.ResourceID() != "doc-1" {
				t.Fatal("binding mismatch")
			}

			if err := h.Gate().Use(
				ctx, exec, "north", "doc-1",
				func(context.Context) error { used = true; return nil },
			); err != nil {
				t.Fatal(err)
			}

			if err := h.Gate().Use(
				ctx, exec, "south", "doc-1",
				func(context.Context) error { return nil },
			); !errors.Is(err, rbac.ErrForbidden) {
				t.Fatalf("other tenant: %v", err)
			}

			return nil
		},
	)
	if err != nil || !used {
		t.Fatalf("err=%v used=%v", err, used)
	}
}

func TestDenialsNeverRunCallback(t *testing.T) {
	deny := options()
	deny.Resource = rbac.ResourcePolicyFunc(
		func(_ context.Context, _ rbac.Request, key string) error {
			if key == "secret" {
				return rbac.ErrForbidden
			}

			return nil
		},
	)

	h, err := identitytest.New(deny)
	if err != nil {
		t.Fatal(err)
	}

	cases := map[string][3]string{
		"no permission":  {"bob", "north", "doc-1"},
		"not a member":   {"alice", "south", "doc-1"},
		"unknown":        {"mallory", "north", "doc-1"},
		"resource deny":  {"alice", "north", "secret"},
		"empty resource": {"alice", "north", ""},
	}

	for name, c := range cases {
		ran := false

		err := h.Within(
			t.Context(), c[0], c[1], c[2],
			func(ctx context.Context, e *identitygate.Execution) error {
				ran = true
				return nil
			},
		)
		if err == nil || ran {
			t.Fatalf("%s: err=%v ran=%v", name, err, ran)
		}
	}
}

func TestExecutionInvalidAfterCallback(t *testing.T) {
	h, err := identitytest.New(options())
	if err != nil {
		t.Fatal(err)
	}

	var escaped *identitygate.Execution

	if err := h.Within(
		t.Context(), "alice", "north", "doc-1",
		func(_ context.Context, e *identitygate.Execution) error {
			escaped = e
			return nil
		},
	); err != nil {
		t.Fatal(err)
	}

	if err := h.Gate().Use(
		t.Context(), escaped, "north", "doc-1",

		func(context.Context) error {
			t.Fatal("ran")

			return nil
		},
	); err == nil {
		t.Fatal("escaped execution accepted")
	}
}

func TestInvalidOptionsRejected(t *testing.T) {
	bad := options()
	bad.Permission = "missing"

	if _, err := identitytest.New(bad); err == nil {
		t.Fatal("unknown permission accepted")
	}

	bad = options()
	bad.Members[0].Roles = []rbac.RoleID{"ghost"}

	h, err := identitytest.New(bad)
	if err == nil {
		if h.Within(t.Context(), "alice", "north", "d", noop) == nil {
			t.Fatal("unknown role granted access")
		}
	}
}
