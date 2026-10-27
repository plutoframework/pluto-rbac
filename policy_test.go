package rbac_test

import (
	"errors"
	"slices"
	"sync"
	"testing"

	rbac "github.com/plutoframework/pluto-rbac"
)

const (
	read    rbac.PermissionID = "purchases:read"
	write   rbac.PermissionID = "purchases:write"
	approve rbac.PermissionID = "purchases:approve"
	manage  rbac.PermissionID = "memberships:manage"

	reader   rbac.RoleID = "reader"
	member   rbac.RoleID = "member"
	reviewer rbac.RoleID = "reviewer"
	admin    rbac.RoleID = "admin"
)

func definition() rbac.Definition {
	return rbac.Definition{
		Permissions: []rbac.Permission{
			{
				ID:          read,
				Name:        "Read",
				Description: "Read permitted purchases.",
			},
			{
				ID:          write,
				Name:        "Write",
				Description: "Create purchase requests.",
			},
			{
				ID:          approve,
				Name:        "Approve",
				Description: "Review colleagues' requests.",
			},
			{
				ID:          manage,
				Name:        "Manage",
				Description: "Manage memberships.",
			},
		},
		Roles: []rbac.Role{
			{
				ID:          admin,
				Name:        "Administrator",
				Description: "Manage the organization.",
				Permissions: []rbac.PermissionID{manage},
				Inherits:    []rbac.RoleID{member, reviewer},
			},
			{
				ID:          reader,
				Name:        "Reader",
				Description: "Read permitted requests.",
				Permissions: []rbac.PermissionID{read},
			},
			{
				ID:          member,
				Name:        "Member",
				Description: "Request purchases.",
				Permissions: []rbac.PermissionID{write},
				Inherits:    []rbac.RoleID{reader},
			},
			{
				ID:          reviewer,
				Name:        "Reviewer",
				Description: "Review requests.",
				Permissions: []rbac.PermissionID{approve},
				Inherits:    []rbac.RoleID{reader},
			},
			{
				ID:          "observer",
				Name:        "Observer",
				Description: "No capabilities yet.",
			},
		},
	}
}

func newPolicy(t testing.TB) *rbac.Policy {
	t.Helper()

	policy, err := rbac.New(definition())
	if err != nil {
		t.Fatal(err)
	}

	return policy
}

func TestPolicyDecisions(t *testing.T) {
	policy := newPolicy(t)

	for _, test := range []struct {
		name       string
		roles      []rbac.RoleID
		permission rbac.PermissionID
		allowed    bool
	}{
		{"direct", []rbac.RoleID{reader}, read, true},
		{"missing grant", []rbac.RoleID{reader}, write, false},
		{"inherited", []rbac.RoleID{member}, read, true},
		{"diamond inheritance", []rbac.RoleID{admin}, read, true},
		{"multiple roles", []rbac.RoleID{member, reviewer}, approve, true},
		{"multiple roles do not imply admin", []rbac.RoleID{member, reviewer}, manage, false},
		{"no roles", nil, read, false},
		{"empty role", []rbac.RoleID{""}, read, false},
		{"unknown role", []rbac.RoleID{"owner"}, read, false},
		{"unknown last", []rbac.RoleID{admin, "owner"}, read, false},
		{"unknown first", []rbac.RoleID{"owner", admin}, read, false},
		{"unknown permission", []rbac.RoleID{admin}, "purchases:delete", false},
		{"empty permission", []rbac.RoleID{admin}, "", false},
		{"no wildcard", []rbac.RoleID{admin}, "purchases:*", false},
		{"no string prefix grant", []rbac.RoleID{reader}, "purchases:read:all", false},
		{"case sensitive", []rbac.RoleID{admin}, "Purchases:read", false},
		{"duplicate assigned roles", []rbac.RoleID{reader, reader}, read, true},
		{"empty role grants", []rbac.RoleID{"observer"}, read, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := policy.Allows(
				test.roles,
				test.permission,
			); got != test.allowed {
				t.Fatalf(
					"Allows(%v, %q)=%v, want %v",
					test.roles,
					test.permission,
					got,
					test.allowed,
				)
			}
		})
	}
}

func TestInvalidDefinitions(t *testing.T) {
	for _, test := range []struct {
		name   string
		change func(*rbac.Definition)
	}{
		{"duplicate permission", func(d *rbac.Definition) {
			d.Permissions = append(d.Permissions, d.Permissions[0])
		}},
		{"duplicate role", func(d *rbac.Definition) {
			d.Roles = append(d.Roles, d.Roles[0])
		}},
		{"unknown grant", func(d *rbac.Definition) {
			d.Roles[0].Permissions = []rbac.PermissionID{"missing"}
		}},
		{"duplicate grant", func(d *rbac.Definition) {
			d.Roles[1].Permissions = []rbac.PermissionID{read, read}
		}},
		{"unknown parent", func(d *rbac.Definition) {
			d.Roles[0].Inherits = []rbac.RoleID{"missing"}
		}},
		{"duplicate parent", func(d *rbac.Definition) {
			d.Roles[0].Inherits = []rbac.RoleID{member, member}
		}},
		{"self cycle", func(d *rbac.Definition) {
			d.Roles[1].Inherits = []rbac.RoleID{reader}
		}},
		{"indirect cycle", func(d *rbac.Definition) {
			d.Roles[1].Inherits = []rbac.RoleID{admin}
		}},
		{"invalid role ID", func(d *rbac.Definition) {
			d.Roles[0].ID = "Admin"
		}},
		{"wildcard permission", func(d *rbac.Definition) {
			d.Permissions[0].ID = "purchases:*"
		}},
		{"empty ID", func(d *rbac.Definition) {
			d.Permissions[0].ID = ""
		}},
		{"consecutive separators", func(d *rbac.Definition) {
			d.Permissions[0].ID = "purchases::read"
		}},
		{"trailing separator", func(d *rbac.Definition) {
			d.Permissions[0].ID = "purchases:"
		}},
		{"name required", func(d *rbac.Definition) {
			d.Roles[0].Name = ""
		}},
		{"description required", func(d *rbac.Definition) {
			d.Permissions[0].Description = ""
		}},
		{"untrimmed display text", func(d *rbac.Definition) {
			d.Roles[0].Name = " Admin"
		}},
		{"control character", func(d *rbac.Definition) {
			d.Permissions[0].Description = "Read\nall"
		}},
		{"invalid UTF8", func(d *rbac.Definition) {
			d.Roles[0].Name = string([]byte{0xff})
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			input := definition()
			test.change(&input)

			policy, err := rbac.New(input)
			if !errors.Is(err, rbac.ErrInvalidPolicy) || policy != nil {
				t.Fatalf(
					"invalid definition accepted: policy=%v err=%v",
					policy,
					err,
				)
			}
		})
	}
}

func TestCatalogCopies(t *testing.T) {
	input := definition()

	policy, err := rbac.New(input)
	if err != nil {
		t.Fatal(err)
	}

	input.Roles[0].Permissions[0] = write
	input.Roles[0].Inherits[0] = "missing"
	input.Roles[1].Permissions[0] = manage
	input.Permissions[0].Name = "Changed input"

	roles := policy.Roles()
	roles[0].Name = "Changed output"
	roles[0].Permissions[0] = write
	roles[0].Inherits[0] = "missing"
	permissions := policy.Permissions()
	permissions[0].Description = "Changed output"

	if policy.Allows([]rbac.RoleID{reader}, manage) ||
		!policy.Allows([]rbac.RoleID{reader}, read) ||
		!policy.Allows([]rbac.RoleID{admin}, manage) {
		t.Fatal("caller changed compiled grants")
	}

	if policy.Roles()[0].Name != "Administrator" ||
		policy.Permissions()[0].Description != "Manage memberships." {
		t.Fatal("caller changed catalog metadata")
	}

	stored := policy.Roles()[0]
	if !slices.Equal(stored.Permissions, []rbac.PermissionID{manage}) ||
		!slices.Equal(stored.Inherits, []rbac.RoleID{member, reviewer}) {
		t.Fatal("caller changed nested role declaration slices")
	}

	got, err := policy.EffectivePermissions(admin)

	want := []rbac.PermissionID{manage, approve, read, write}
	if err != nil || !slices.Equal(got, want) {
		t.Fatalf("effective=%v, err=%v", got, err)
	}

	got[0] = "missing"

	if !policy.Allows([]rbac.RoleID{admin}, manage) {
		t.Fatal("effective permission output mutated grants")
	}

	if _, err := policy.EffectivePermissions(
		"missing",
	); !errors.Is(
		err,
		rbac.ErrUnknownRole,
	) {
		t.Fatalf("unknown role error=%v", err)
	}
}

func TestEmptyAndNilPolicy(t *testing.T) {
	empty, err := rbac.New(rbac.Definition{})
	if err != nil {
		t.Fatal(err)
	}

	var (
		nilPolicy  *rbac.Policy
		zeroPolicy rbac.Policy
	)

	for _, policy := range []*rbac.Policy{empty, &zeroPolicy, nilPolicy} {
		if policy.Allows([]rbac.RoleID{admin}, read) ||
			len(policy.Roles()) != 0 || len(policy.Permissions()) != 0 {
			t.Fatal("empty policy granted access or exposed a catalog")
		}

		if _, err := policy.EffectivePermissions(
			admin,
		); !errors.Is(
			err,
			rbac.ErrUnknownRole,
		) {
			t.Fatalf("zero policy error=%v", err)
		}
	}
}

func TestConcurrentReads(t *testing.T) {
	policy := newPolicy(t)

	var workers sync.WaitGroup

	for range 16 {
		workers.Go(func() {
			for range 100 {
				if !policy.Allows([]rbac.RoleID{admin}, read) {
					t.Error("concurrent read denied")
				}

				roles := policy.Roles()
				roles[0].Inherits[0] = "caller-mutation"
			}
		})
	}

	workers.Wait()
}
