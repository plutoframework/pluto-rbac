// Package identitytest mints identitygate executions for tests of authored
// code. It builds a real session manager, RBAC authorizer and identity gate
// from an in-memory membership table, so a test exercises the same authority
// path as production: session verification, current membership, permission
// resolution and resource policy.
//
// This package is test-only by convention. Production code must not import it:
// its membership table is process-local and its default resource policy admits
// every resource key. It offers no way to construct an execution without the
// gate, and executions are valid only inside the Within callback, exactly as in
// production.
package identitytest

import (
	"context"
	"time"

	rbac "github.com/plutoframework/pluto-rbac"
	identitygate "github.com/plutoframework/pluto-rbac/identity"

	auth "github.com/plutoframework/pluto-auth"
	"github.com/plutoframework/pluto-auth/stores/memory"
)

const (
	sessionCapacity = 64
	sessionTTL      = time.Hour
)

// Member grants one subject roles within one tenant. A subject with no Member
// for a tenant fails the membership check for that tenant.
type Member struct {
	SubjectID string
	TenantID  string
	Roles     []rbac.RoleID
}

// Options configures a Harness. Policy, Permission and Members are required.
type Options struct {

	// Policy is the application's real RBAC definition.
	Policy rbac.Definition

	// Permission is the permission the gate requires for every execution.
	Permission rbac.PermissionID

	// Members is the in-memory membership and role assignment table.
	Members []Member

	// Resource is the application resource policy. A nil policy admits every
	// resource key; supply one to test resource denial.
	Resource rbac.ResourcePolicy
}

// Harness owns a real gate backed by in-memory sessions and membership.
type Harness struct {
	manager *auth.Manager
	gate    *identitygate.Gate
}

// New builds the gate. Invalid policies, unknown roles and duplicate members
// are rejected by the underlying RBAC and membership validation.
func New(options Options) (*Harness, error) {
	policy, err := rbac.New(options.Policy)
	if err != nil {
		return nil, err
	}

	assignments := make([]rbac.Assignment, 0, len(options.Members))
	members := make(map[[2]string]bool, len(options.Members))

	for _, member := range options.Members {
		assignments = append(assignments, rbac.Assignment{
			SubjectID: member.SubjectID,
			Scope:     rbac.Scope{TenantID: member.TenantID},
			Roles:     member.Roles,
		})
		members[[2]string{member.SubjectID, member.TenantID}] = true
	}

	resolver, err := rbac.NewStaticResolver(assignments)
	if err != nil {
		return nil, err
	}

	authorizer, err := rbac.NewAuthorizer(
		policy,
		resolver,
		rbac.Options{RequireTenant: true},
	)
	if err != nil {
		return nil, err
	}

	permission, err := authorizer.Require(options.Permission)
	if err != nil {
		return nil, err
	}

	resource := options.Resource
	if resource == nil {
		resource = rbac.ResourcePolicyFunc(allowResource)
	}

	requirement, err := permission.WithResourcePolicy(resource)
	if err != nil {
		return nil, err
	}

	store, err := memory.New(sessionCapacity)
	if err != nil {
		return nil, err
	}

	manager, err := auth.New(
		store,
		auth.Config{TTL: sessionTTL, Clock: time.Now},
	)
	if err != nil {
		return nil, err
	}

	gate, err := identitygate.New(
		manager,
		requirement,
		identitygate.MembershipVerifierFunc(
			func(_ context.Context, subject, tenant string) error {
				if !members[[2]string{subject, tenant}] {
					return rbac.ErrForbidden
				}

				return nil
			},
		),
	)
	if err != nil {
		return nil, err
	}

	return &Harness{manager: manager, gate: gate}, nil
}

func allowResource(context.Context, rbac.Request, string) error {
	return nil
}

// Gate returns the real gate. Pass it to code under test that calls Use.
func (h *Harness) Gate() *identitygate.Gate {
	return h.gate
}

// Within starts a fresh session for subject and runs run with an execution
// bound to subject, tenant and resource through the real gate. Denials from
// authentication, membership, permission or resource policy are returned
// unchanged and run is not invoked. The execution is valid only until run
// returns.
func (h *Harness) Within(
	ctx context.Context,
	subject, tenant, resource string,
	run func(context.Context, *identitygate.Execution) error,
) error {
	issued, err := h.manager.Start(ctx, subject)
	if err != nil {
		return err
	}

	defer func() { _ = h.manager.Revoke(context.WithoutCancel(ctx), issued.Token) }()

	return h.manager.WithIdentity(
		ctx,
		issued.Token,
		func(ctx context.Context, identity *auth.Identity) error {
			return h.gate.Within(ctx, identity, tenant, resource, run)
		},
	)
}
