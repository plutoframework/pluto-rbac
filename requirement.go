package rbac

import "context"

// Requirement binds a required permission to an authorizer. Its zero value denies.
// It is not an authorization result or a reusable proof of a previous grant.
// Construct it once per operation with Authorizer.Require.
type Requirement struct {
	authorizer *Authorizer
	permission PermissionID
}

// Require binds a known permission for subsequent gated executions. It does not
// resolve assignments or grant authority; Execute resolves each invocation.
func (a *Authorizer) Require(permission PermissionID) (*Requirement, error) {
	if a == nil || a.policy == nil || a.resolver == nil {
		return nil, ErrUnconfigured
	}

	if _, known := a.policy.permissions[permission]; !known {
		return nil, ErrForbidden
	}

	return &Requirement{authorizer: a, permission: permission}, nil
}

// Execute invokes run only after resolving the subject's current roles for the
// bound permission in this exact scope. Subject and scope must come from trusted
// application wiring. A nil callback is an invalid request.
//
// The callback owns resource policy and transaction checks. Authorization is not
// atomic with its effects: revocation may race execution, and resolver freshness
// still applies. Keep the underlying mutation private to the operation; this API
// cannot prevent direct calls to separately exposed writes or captured callbacks.
func (r *Requirement) Execute(
	ctx context.Context,
	subjectID string,
	scope Scope,
	run func(context.Context) error,
) error {
	if r == nil || r.authorizer == nil {
		return ErrUnconfigured
	}

	if run == nil {
		return ErrInvalidRequest
	}

	if err := r.authorizer.Authorize(ctx, Request{
		SubjectID:  subjectID,
		Scope:      scope,
		Permission: r.permission,
	}); err != nil {
		return err
	}

	if err := ctx.Err(); err != nil {
		return err
	}

	return run(ctx)
}
