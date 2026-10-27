package rbac

import (
	"fmt"
	"slices"
)

// Policy is a compiled immutable catalog. Its zero value denies every check.
type Policy struct {
	permissions   map[PermissionID]Permission
	roles         map[RoleID]Role
	grants        map[RoleID]map[PermissionID]struct{}
	roleIDs       []RoleID
	permissionIDs []PermissionID
}

// New validates and copies a definition, rejecting cycles and unknown grants.
// An empty definition is valid and grants nothing.
func New(definition Definition) (*Policy, error) {
	policy := &Policy{
		permissions: make(map[PermissionID]Permission),
		roles:       make(map[RoleID]Role),
		grants:      make(map[RoleID]map[PermissionID]struct{}),
	}

	for _, permission := range definition.Permissions {
		if !validID(string(permission.ID)) || !validText(permission.Name) ||
			!validText(permission.Description) {
			return nil, fmt.Errorf(
				"%w: permission %q needs a valid ID, name and description",
				ErrInvalidPolicy,
				permission.ID,
			)
		}

		if _, exists := policy.permissions[permission.ID]; exists {
			return nil, fmt.Errorf(
				"%w: duplicate permission %q",
				ErrInvalidPolicy,
				permission.ID,
			)
		}

		policy.permissions[permission.ID] = permission
		policy.permissionIDs = append(policy.permissionIDs, permission.ID)
	}

	for _, role := range definition.Roles {
		if !validID(string(role.ID)) || !validText(role.Name) ||
			!validText(role.Description) {
			return nil, fmt.Errorf(
				"%w: role %q needs a valid ID, name and description",
				ErrInvalidPolicy,
				role.ID,
			)
		}

		if _, exists := policy.roles[role.ID]; exists {
			return nil, fmt.Errorf(
				"%w: duplicate role %q",
				ErrInvalidPolicy,
				role.ID,
			)
		}

		policy.roles[role.ID] = copyRole(role)
		policy.roleIDs = append(policy.roleIDs, role.ID)
	}

	slices.Sort(policy.roleIDs)
	slices.Sort(policy.permissionIDs)

	if err := policy.compile(); err != nil {
		return nil, err
	}

	return policy, nil
}

// Allows evaluates trusted role IDs. It does not authenticate a subject.
// Any unknown role invalidates the entire assignment, even beside a known role.
func (p *Policy) Allows(roles []RoleID, permission PermissionID) bool {
	if p == nil {
		return false
	}

	if _, exists := p.permissions[permission]; !exists {
		return false
	}

	for _, role := range roles {
		if _, exists := p.roles[role]; !exists {
			return false
		}
	}

	for _, role := range roles {
		if _, granted := p.grants[role][permission]; granted {
			return true
		}
	}

	return false
}

// Permissions returns a defensive copy sorted by stable ID.
func (p *Policy) Permissions() []Permission {
	if p == nil {
		return nil
	}

	result := make([]Permission, 0, len(p.permissionIDs))

	for _, id := range p.permissionIDs {
		result = append(result, p.permissions[id])
	}

	return result
}

// Roles returns defensive copies, including direct grants and inheritance.
// Results are sorted by stable ID; each role's slices retain declaration order.
func (p *Policy) Roles() []Role {
	if p == nil {
		return nil
	}

	result := make([]Role, 0, len(p.roleIDs))

	for _, id := range p.roleIDs {
		result = append(result, copyRole(p.roles[id]))
	}

	return result
}

// EffectivePermissions returns direct and inherited grants sorted by ID.
func (p *Policy) EffectivePermissions(role RoleID) ([]PermissionID, error) {
	if p == nil {
		return nil, ErrUnknownRole
	}

	grants, exists := p.grants[role]
	if !exists {
		return nil, fmt.Errorf("%w: %q", ErrUnknownRole, role)
	}

	result := make([]PermissionID, 0, len(grants))

	for permission := range grants {
		result = append(result, permission)
	}

	slices.Sort(result)

	return result, nil
}

func copyRole(role Role) Role {
	role.Permissions = slices.Clone(role.Permissions)
	role.Inherits = slices.Clone(role.Inherits)

	return role
}
