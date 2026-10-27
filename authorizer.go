package rbac

import (
	"context"
	"fmt"
	"reflect"
)

// Scope is unscoped when TenantID is empty. There is no wildcard scope.
type Scope struct {
	TenantID string
}

// Request carries a subject already authenticated by the application.
// A subject ID or tenant supplied by an unverified client is not trustworthy.
type Request struct {
	SubjectID  string
	Scope      Scope
	Permission PermissionID
}

// RoleResolver must resolve only this subject in this exact scope.
// It must not fall back to a different tenant or to global assignments.
// Implementations must support concurrent calls if the authorizer is shared.
// Returned slices must be immutable or owned by the caller.
type RoleResolver interface {
	Roles(context.Context, string, Scope) ([]RoleID, error)
}

// RoleResolverFunc adapts a function for simple adapters and tests.
type RoleResolverFunc func(context.Context, string, Scope) ([]RoleID, error)

func (f RoleResolverFunc) Roles(
	ctx context.Context,
	subjectID string,
	scope Scope,
) ([]RoleID, error) {
	if f == nil {
		return nil, ErrInvalidResolver
	}

	return f(ctx, subjectID, scope)
}

// Options defaults to single tenancy. Single tenancy rejects nonempty tenants;
// tenant mode requires a tenant for every request, preventing mixed-scope use.
type Options struct {
	RequireTenant bool
}

// Authorizer composes an immutable policy with assignment resolution.
// It does not cache assignments. Resolver errors deny; cancellation is checked
// before and after resolution.
type Authorizer struct {
	policy        *Policy
	resolver      RoleResolver
	requireTenant bool
}

// NewAuthorizer requires a policy and a nonnil role resolver. Options explicitly
// select tenant-scoped checks; their zero value selects unscoped checks.
func NewAuthorizer(
	policy *Policy,
	resolver RoleResolver,
	options Options,
) (*Authorizer, error) {
	if policy == nil {
		return nil, ErrUnconfigured
	}

	if resolver == nil {
		return nil, ErrInvalidResolver
	}

	value := reflect.ValueOf(resolver)
	if (value.Kind() == reflect.Pointer || value.Kind() == reflect.Func ||
		value.Kind() == reflect.Map || value.Kind() == reflect.Slice ||
		value.Kind() == reflect.Chan) && value.IsNil() {
		return nil, ErrInvalidResolver
	}

	return &Authorizer{
		policy:        policy,
		resolver:      resolver,
		requireTenant: options.RequireTenant,
	}, nil
}

// Authorize returns nil only for a known permission granted by resolved roles.
// Unknown role IDs invalidate the whole assignment, including other valid roles.
// Resolver errors retain their underlying cause; do not expose them over HTTP.
func (a *Authorizer) Authorize(ctx context.Context, request Request) error {
	if a == nil || a.policy == nil || a.resolver == nil {
		return ErrUnconfigured
	}

	if ctx == nil {
		return ErrInvalidRequest
	}

	if err := ctx.Err(); err != nil {
		return err
	}

	if !validText(request.SubjectID) {
		return ErrUnauthenticated
	}

	if a.requireTenant {
		if !validText(request.Scope.TenantID) {
			return ErrInvalidRequest
		}
	} else if request.Scope.TenantID != "" {
		return ErrInvalidRequest
	}

	if _, known := a.policy.permissions[request.Permission]; !known {
		return ErrForbidden
	}

	roles, err := a.resolver.Roles(ctx, request.SubjectID, request.Scope)
	if contextErr := ctx.Err(); contextErr != nil {
		return contextErr
	}

	if err != nil {
		return fmt.Errorf("%w: %w", ErrResolveRoles, err)
	}

	if !a.policy.Allows(roles, request.Permission) {
		return ErrForbidden
	}

	return nil
}
