package rbac

import "errors"

// PermissionID is a stable capability, independent of route names and paths.
type PermissionID string

// RoleID identifies an application-defined role.
type RoleID string

// Permission includes display metadata for documentation or assignment UIs.
type Permission struct {
	ID          PermissionID
	Name        string
	Description string
}

// Role grants its direct permissions plus those of every role in Inherits.
// Inheritance grants permissions; it does not assign users or cross scopes.
type Role struct {
	ID          RoleID
	Name        string
	Description string
	Permissions []PermissionID
	Inherits    []RoleID
}

// Definition is application-owned input. New copies and validates its contents.
type Definition struct {
	Permissions []Permission
	Roles       []Role
}

var (
	ErrInvalidPolicy   = errors.New("invalid RBAC policy")
	ErrUnknownRole     = errors.New("unknown RBAC role")
	ErrInvalidRequest  = errors.New("invalid authorization request")
	ErrUnauthenticated = errors.New("authenticated subject required")
	ErrForbidden       = errors.New("permission denied")
	ErrResolveRoles    = errors.New("role resolution failed")
	ErrInvalidResolver = errors.New("invalid role resolver")
	ErrUnconfigured    = errors.New("RBAC authorizer is not configured")
)
