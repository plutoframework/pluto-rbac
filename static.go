package rbac

import (
	"context"
	"fmt"
	"slices"
)

// Assignment binds a subject's roles to one exact scope.
type Assignment struct {
	SubjectID string
	Scope     Scope
	Roles     []RoleID
}

type assignmentKey struct {
	subjectID string
	scope     Scope
}

// StaticResolver is an immutable assignment snapshot, useful for tests or
// startup-loaded data. Its zero value resolves no roles. Revocations require
// replacing the snapshot; use a live resolver when assignments must change.
type StaticResolver struct {
	assignments map[assignmentKey][]RoleID
}

// NewStaticResolver copies assignments and rejects duplicate subject/scope keys.
// Unknown role IDs are rejected by Authorizer against its current policy.
func NewStaticResolver(assignments []Assignment) (*StaticResolver, error) {
	resolver := &StaticResolver{
		assignments: make(map[assignmentKey][]RoleID, len(assignments)),
	}

	for _, assignment := range assignments {
		if !validText(assignment.SubjectID) ||
			assignment.Scope.TenantID != "" &&
				!validText(assignment.Scope.TenantID) {
			return nil, fmt.Errorf(
				"%w: assignment needs a subject and a valid scope",
				ErrInvalidResolver,
			)
		}

		key := assignmentKey{assignment.SubjectID, assignment.Scope}
		if _, duplicate := resolver.assignments[key]; duplicate {
			return nil, fmt.Errorf(
				"%w: duplicate subject/scope assignment",
				ErrInvalidResolver,
			)
		}

		seen := make(map[RoleID]bool, len(assignment.Roles))

		for _, role := range assignment.Roles {
			if !validID(string(role)) || seen[role] {
				return nil, fmt.Errorf(
					"%w: invalid or repeated role %q",
					ErrInvalidResolver,
					role,
				)
			}

			seen[role] = true
		}

		resolver.assignments[key] = slices.Clone(assignment.Roles)
	}

	return resolver, nil
}

func (s *StaticResolver) Roles(
	ctx context.Context,
	subjectID string,
	scope Scope,
) ([]RoleID, error) {
	if ctx == nil {
		return nil, ErrInvalidRequest
	}

	if err := ctx.Err(); err != nil {
		return nil, err
	}

	if s == nil {
		return nil, ErrInvalidResolver
	}

	roles := s.assignments[assignmentKey{subjectID, scope}]

	return slices.Clone(roles), nil
}
