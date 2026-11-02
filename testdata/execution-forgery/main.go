// This external consumer must not compile: execution authority is opaque.
package forgery

import rbac "github.com/plutoframework/pluto-rbac"

var forged = rbac.Execution{state: nil}
