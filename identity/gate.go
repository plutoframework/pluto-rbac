// Package identitygate composes concrete session identity, current membership,
// permissions and mandatory application resource policy. It is an unreleased
// optional integration module; Auth/RBAC roots remain standard-library-only.
package identitygate

import (
	"context"
	"reflect"

	rbac "github.com/plutoframework/pluto-rbac"

	auth "github.com/plutoframework/pluto-auth"
)

type MembershipVerifier interface {
	VerifyMembership(context.Context, string, string) error
}
type MembershipVerifierFunc func(context.Context, string, string) error

func (f MembershipVerifierFunc) VerifyMembership(
	ctx context.Context,
	subject, tenant string,
) error {
	if f == nil {
		return rbac.ErrForbidden
	}

	return f(ctx, subject, tenant)
}

type Gate struct {
	issuer      *auth.Manager
	requirement *rbac.ResourceRequirement
	membership  MembershipVerifier
}

// Execution has no public constructor. Actor and selected tenant come from the
// issuer's session verification plus the configured current membership verifier.
// It retains no bearer credential and cannot escape either callback lifetime.
type Execution struct {
	gate       *Gate
	identity   *auth.Identity
	permission *rbac.Execution
	subject    string
	tenant     string
	resource   string
}

func New(
	issuer *auth.Manager,
	requirement *rbac.ResourceRequirement,
	membership MembershipVerifier,
) (*Gate, error) {
	if issuer == nil || requirement == nil || membership == nil {
		return nil, rbac.ErrUnconfigured
	}

	value := reflect.ValueOf(membership)
	if (value.Kind() == reflect.Pointer || value.Kind() == reflect.Func ||
		value.Kind() == reflect.Map || value.Kind() == reflect.Slice ||
		value.Kind() == reflect.Chan) && value.IsNil() {
		return nil, rbac.ErrUnconfigured
	}

	return &Gate{
		issuer:      issuer,
		requirement: requirement,
		membership:  membership,
	}, nil
}

func (g *Gate) Within(
	ctx context.Context,
	identity *auth.Identity,
	tenant, resource string,
	run func(context.Context, *Execution) error,
) error {
	if g == nil || g.issuer == nil || g.requirement == nil ||
		g.membership == nil {
		return rbac.ErrUnconfigured
	}

	if run == nil {
		return rbac.ErrInvalidRequest
	}

	return g.issuer.UseIdentity(
		ctx,
		identity,
		func(ctx context.Context, subject string) error {
			if err := g.membership.VerifyMembership(
				ctx,
				subject,
				tenant,
			); err != nil {
				return err
			}

			return g.requirement.Within(
				ctx,
				subject,
				rbac.Scope{TenantID: tenant},
				resource,
				func(ctx context.Context, permission *rbac.Execution) error {
					return g.withCurrentIdentity(
						ctx,
						identity,
						subject,
						func(ctx context.Context) error {
							return run(ctx, &Execution{
								gate:       g,
								identity:   identity,
								permission: permission,
								subject:    subject,
								tenant:     tenant,
								resource:   resource,
							})
						},
					)
				},
			)
		},
	)
}

// Use verifies the exact gate/binding, live issuing session, current membership,
// current permission and current resource policy before invoking a data callback.
// The target binding must come from the scoped record/query or evaluated change.
// None of these checks establish transaction atomicity with mutable auth facts.
func (g *Gate) Use(
	ctx context.Context,
	execution *Execution,
	tenant, resource string,
	run func(context.Context) error,
) error {
	if g == nil || g.issuer == nil || g.requirement == nil ||
		g.membership == nil {
		return rbac.ErrUnconfigured
	}

	if run == nil {
		return rbac.ErrInvalidRequest
	}

	if execution == nil || execution.gate != g || execution.identity == nil ||
		execution.permission == nil ||
		execution.tenant != tenant ||
		execution.resource != resource {
		return rbac.ErrForbidden
	}

	return g.issuer.UseIdentity(
		ctx,
		execution.identity,
		func(ctx context.Context, subject string) error {
			if subject != execution.subject {
				return auth.ErrUnauthenticated
			}

			if err := g.membership.VerifyMembership(
				ctx,
				subject,
				tenant,
			); err != nil {
				return err
			}

			return g.requirement.Use(
				ctx,
				execution.permission,
				subject,
				rbac.Scope{TenantID: tenant},
				resource,
				func(ctx context.Context) error {
					return g.withCurrentIdentity(
						ctx,
						execution.identity,
						subject,
						run,
					)
				},
			)
		},
	)
}

// SubjectID, TenantID and ResourceID expose binding facts, never reusable proof.
// Passing their strings to a different API does not verify that API's authority.
func (e *Execution) SubjectID() string {
	if e == nil {
		return ""
	}

	return e.subject
}

func (e *Execution) TenantID() string {
	if e == nil {
		return ""
	}

	return e.tenant
}

func (e *Execution) ResourceID() string {
	if e == nil {
		return ""
	}

	return e.resource
}

// Policy evaluation may perform I/O. Recheck the original identity after those
// callbacks, including its original context even if the caller supplied another.
func (g *Gate) withCurrentIdentity(
	ctx context.Context,
	identity *auth.Identity,
	subject string,
	run func(context.Context) error,
) error {
	return g.issuer.UseIdentity(
		ctx,
		identity,
		func(ctx context.Context, current string) error {
			if current != subject {
				return auth.ErrUnauthenticated
			}

			return run(ctx)
		},
	)
}
