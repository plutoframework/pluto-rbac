package rbac

import "fmt"

// compile resolves parents before children without recursive graph traversal.
func (p *Policy) compile() error {
	pending := make(map[RoleID]int, len(p.roles))
	children := make(map[RoleID][]RoleID, len(p.roles))
	ready := make([]RoleID, 0, len(p.roles))

	for _, id := range p.roleIDs {
		role := p.roles[id]
		grants := make(map[PermissionID]struct{}, len(role.Permissions))

		for _, permission := range role.Permissions {
			if _, exists := p.permissions[permission]; !exists {
				return fmt.Errorf(
					"%w: role %q grants unknown permission %q",
					ErrInvalidPolicy,
					id,
					permission,
				)
			}

			if _, duplicate := grants[permission]; duplicate {
				return fmt.Errorf(
					"%w: role %q repeats permission %q",
					ErrInvalidPolicy,
					id,
					permission,
				)
			}

			grants[permission] = struct{}{}
		}

		p.grants[id] = grants
		parents := make(map[RoleID]bool, len(role.Inherits))

		for _, parent := range role.Inherits {
			if _, exists := p.roles[parent]; !exists || parents[parent] {
				return fmt.Errorf(
					"%w: role %q has unknown or repeated parent %q",
					ErrInvalidPolicy,
					id,
					parent,
				)
			}

			parents[parent] = true
			children[parent] = append(children[parent], id)
		}

		pending[id] = len(role.Inherits)
		if pending[id] == 0 {
			ready = append(ready, id)
		}
	}

	for index := 0; index < len(ready); index++ {
		parent := ready[index]

		for _, child := range children[parent] {
			for permission := range p.grants[parent] {
				p.grants[child][permission] = struct{}{}
			}

			pending[child]--
			if pending[child] == 0 {
				ready = append(ready, child)
			}
		}
	}

	if len(ready) != len(p.roles) {
		return fmt.Errorf(
			"%w: role inheritance contains a cycle",
			ErrInvalidPolicy,
		)
	}

	return nil
}
