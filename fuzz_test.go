package rbac_test

import (
	"context"
	"fmt"
	"testing"

	rbac "github.com/plutoframework/pluto-rbac"
)

// The oracle walks assignments through direct grants, independently of the
// production compiler's topological expansion of effective permissions.
func FuzzPolicyMatchesReference(f *testing.F) {
	f.Add([]byte{1, 7, 3, 5, 15, 31, 63})
	f.Add([]byte{0})
	f.Add([]byte{255, 255, 255})

	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) == 0 {
			return
		}

		byteAt := func(index int) byte { return data[index%len(data)] }
		input := rbac.Definition{}

		for index := range 4 {
			input.Permissions = append(input.Permissions, rbac.Permission{
				ID: rbac.PermissionID(
					fmt.Sprintf("permission-%d", index),
				),
				Name:        "Permission",
				Description: "A fuzz capability.",
			})
		}

		for index := range 6 {
			role := rbac.Role{
				ID:          rbac.RoleID(fmt.Sprintf("role-%d", index)),
				Name:        "Role",
				Description: "A fuzz role.",
			}

			for permission := range 4 {
				if byteAt(index+1)&(1<<permission) != 0 {
					role.Permissions = append(
						role.Permissions,
						input.Permissions[permission].ID,
					)
				}
			}

			for parent := range index {
				if byteAt(index+7)&(1<<parent) != 0 {
					role.Inherits = append(
						role.Inherits,
						input.Roles[parent].ID,
					)
				}
			}

			input.Roles = append(input.Roles, role)
		}

		policy, err := rbac.New(input)
		if err != nil {
			t.Fatal(err)
		}

		assigned := []rbac.RoleID{}

		for index, role := range input.Roles {
			if byteAt(13)&(1<<index) != 0 {
				assigned = append(assigned, role.ID)
			}
		}

		if byteAt(14)&128 != 0 {
			assigned = append(assigned, "unknown")
		}

		for _, permission := range append(
			append([]rbac.Permission(nil), input.Permissions...),
			rbac.Permission{ID: "unknown"},
		) {
			want := referenceAllows(input, assigned, permission.ID)
			if got := policy.Allows(assigned, permission.ID); got != want {
				t.Fatalf(
					"roles=%v permission=%s got=%v want=%v",
					assigned,
					permission.ID,
					got,
					want,
				)
			}
		}
	})
}

func referenceAllows(
	definition rbac.Definition,
	assigned []rbac.RoleID,
	permission rbac.PermissionID,
) bool {
	roles := map[rbac.RoleID]rbac.Role{}
	for _, role := range definition.Roles {
		roles[role.ID] = role
	}

	for _, role := range assigned {
		if _, known := roles[role]; !known {
			return false
		}
	}

	queue := append([]rbac.RoleID(nil), assigned...)
	seen := map[rbac.RoleID]bool{}

	for len(queue) > 0 {
		id := queue[0]
		queue = queue[1:]

		if seen[id] {
			continue
		}

		seen[id] = true

		role := roles[id]
		for _, grant := range role.Permissions {
			if grant == permission {
				return true
			}
		}

		queue = append(queue, role.Inherits...)
	}

	return false
}

func FuzzTenantIsolation(f *testing.F) {
	f.Add("alice", "north", "harbor")
	f.Add("alice", "", "north")
	f.Add("alice", "north", "")

	f.Fuzz(func(t *testing.T, subject, assignedTenant, requestedTenant string) {
		if assignedTenant == requestedTenant {
			return
		}

		resolver, err := rbac.NewStaticResolver([]rbac.Assignment{
			{
				SubjectID: subject,
				Scope:     rbac.Scope{TenantID: assignedTenant},
				Roles:     []rbac.RoleID{admin},
			},
		})
		if err != nil {
			return
		}

		authorizer := newAuthorizer(t, resolver, true)

		err = authorizer.Authorize(context.Background(), rbac.Request{
			SubjectID:  subject,
			Scope:      rbac.Scope{TenantID: requestedTenant},
			Permission: manage,
		})
		if err == nil {
			t.Fatal("privileged assignment crossed a tenant boundary")
		}
	})
}
