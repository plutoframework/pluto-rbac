// Package rbac compiles named roles and permissions into immutable policies.
//
// Policies grant exact permissions, optionally through role inheritance. Checks
// deny unknown permissions, unknown roles, and empty role assignments. There are
// no wildcard permissions, implicit administrators, or explicit deny rules.
//
// Authorizer resolves assignments for an authenticated subject in an explicit
// scope. Tenant mode requires a tenant and never falls back to unscoped roles.
// Authentication, resource ownership, tenant selection/membership verification,
// assignment persistence, and transactional revocation belong to the application.
//
// Compiled policies and static resolvers are immutable and safe for concurrent
// reads. Custom role resolvers must provide their own concurrency guarantees.
package rbac
