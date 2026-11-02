package rbac

import (
	"context"
	"reflect"
)

// ResourcePolicy evaluates application-owned resource authorization. A
// permission
// grant alone cannot prove ownership or business eligibility. Implementations
// must load current scoped facts as needed; every nonnil error denies
// execution.
// Implementations must support concurrent calls when the gate is shared.
type ResourcePolicy interface {
	AuthorizeResource(context.Context, Request, string) error
}

type ResourcePolicyFunc func(context.Context, Request, string) error

func (f ResourcePolicyFunc) AuthorizeResource(
	ctx context.Context,
	request Request,
	resourceID string,
) error {
	if f == nil {
		return ErrForbidden
	}

	return f(ctx, request, resourceID)
}

// ResourceRequirement requires current permission and resource policy at entry
// and every guarded use. Its private requirement instance prevents a separately
// held permission-only Requirement from using its executions without the
// policy.
type ResourceRequirement struct {
	requirement *Requirement
	policy      ResourcePolicy
}

func (r *Requirement) WithResourcePolicy(
	policy ResourcePolicy,
) (*ResourceRequirement, error) {
	if r == nil || r.authorizer == nil {
		return nil, ErrUnconfigured
	}

	if policy == nil {
		return nil, ErrInvalidRequest
	}

	value := reflect.ValueOf(policy)
	if (value.Kind() == reflect.Pointer ||
		value.Kind() == reflect.Func ||
		value.Kind() == reflect.Map ||
		value.Kind() == reflect.Slice ||
		value.Kind() == reflect.Chan) &&
		value.IsNil() {
		return nil, ErrInvalidRequest
	}

	private := &Requirement{authorizer: r.authorizer, permission: r.permission}

	return &ResourceRequirement{requirement: private, policy: policy}, nil
}

func (r *ResourceRequirement) Within(
	ctx context.Context,
	subject string,
	scope Scope,
	resource string,
	run func(context.Context, *Execution) error,
) error {
	if r == nil || r.requirement == nil || r.policy == nil {
		return ErrUnconfigured
	}

	if run == nil {
		return ErrInvalidRequest
	}

	return r.requirement.Within(
		ctx,
		subject,
		scope,
		resource,
		func(ctx context.Context, execution *Execution) error {
			if err := r.policy.AuthorizeResource(
				ctx,
				Request{
					SubjectID:  subject,
					Scope:      scope,
					Permission: r.requirement.permission,
				},
				resource,
			); err != nil {
				return err
			}

			if err := ctx.Err(); err != nil {
				return err
			}

			return run(ctx, execution)
		},
	)
}

func (r *ResourceRequirement) Use(
	ctx context.Context,
	execution *Execution,
	subject string,
	scope Scope,
	resource string,
	run func(context.Context) error,
) error {
	if r == nil || r.requirement == nil || r.policy == nil {
		return ErrUnconfigured
	}

	if run == nil {
		return ErrInvalidRequest
	}

	return r.requirement.Use(
		ctx,
		execution,
		subject,
		scope,
		resource,
		func(ctx context.Context) error {
			if err := r.policy.AuthorizeResource(
				ctx,
				Request{
					SubjectID:  subject,
					Scope:      scope,
					Permission: r.requirement.permission,
				},
				resource,
			); err != nil {
				return err
			}

			if err := ctx.Err(); err != nil {
				return err
			}

			return run(ctx)
		},
	)
}
