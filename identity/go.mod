module github.com/plutoframework/pluto-rbac/identity

go 1.25.5

require (
 github.com/plutoframework/pluto-auth v0.0.0
 github.com/plutoframework/pluto-rbac v0.0.0
)

// Unreleased candidate integration; no published dependency claim.
replace github.com/plutoframework/pluto-auth => ../../pluto-auth
replace github.com/plutoframework/pluto-rbac => ..
