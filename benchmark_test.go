package rbac_test

import (
	"context"
	"testing"

	rbac "github.com/plutoframework/pluto-rbac"
)

func BenchmarkPolicyAllows(b *testing.B) {
	policy := newPolicy(b)
	roles := []rbac.RoleID{admin}

	b.ReportAllocs()
	b.ResetTimer()

	for b.Loop() {
		if !policy.Allows(roles, read) {
			b.Fatal("unexpected denial")
		}
	}
}

func BenchmarkAuthorizeStatic(b *testing.B) {
	resolver, err := rbac.NewStaticResolver([]rbac.Assignment{
		{
			SubjectID: "alice",
			Scope:     rbac.Scope{TenantID: "north"},
			Roles:     []rbac.RoleID{admin},
		},
	})
	if err != nil {
		b.Fatal(err)
	}

	authorizer := newAuthorizer(b, resolver, true)
	request := rbac.Request{
		SubjectID:  "alice",
		Scope:      rbac.Scope{TenantID: "north"},
		Permission: read,
	}
	ctx := context.Background()

	b.ReportAllocs()
	b.ResetTimer()

	for b.Loop() {
		if err := authorizer.Authorize(ctx, request); err != nil {
			b.Fatal(err)
		}
	}
}
