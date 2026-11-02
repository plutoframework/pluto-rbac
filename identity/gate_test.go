package identitygate_test

import (
	"context"
	"errors"
	"testing"
	"time"

	rbac "github.com/plutoframework/pluto-rbac"
	identitygate "github.com/plutoframework/pluto-rbac/identity"

	auth "github.com/plutoframework/pluto-auth"
	"github.com/plutoframework/pluto-auth/stores/memory"
)

type fixture struct {
	manager        *auth.Manager
	token          string
	gate           *identitygate.Gate
	membership     bool
	resource       bool
	roles          []rbac.RoleID
	beforeResource func()
	requirement    *rbac.ResourceRequirement
}

func newManager(t *testing.T) *auth.Manager {
	t.Helper()

	store, err := memory.New(10)
	if err != nil {
		t.Fatal(err)
	}

	manager, err := auth.New(
		store,
		auth.Config{TTL: time.Hour, Clock: time.Now},
	)
	if err != nil {
		t.Fatal(err)
	}

	return manager
}

func setup(t *testing.T) *fixture {
	t.Helper()

	f := &fixture{
		manager:    newManager(t),
		membership: true,
		resource:   true,
		roles:      []rbac.RoleID{"reviewer"},
	}

	issued, err := f.manager.Start(t.Context(), "alice")
	if err != nil {
		t.Fatal(err)
	}

	f.token = issued.Token

	policy, err := rbac.New(rbac.Definition{
		Permissions: []rbac.Permission{
			{ID: "review", Name: "Review", Description: "Review resource"},
		},
		Roles: []rbac.Role{
			{
				ID:          "reviewer",
				Name:        "Reviewer",
				Description: "Review resource",
				Permissions: []rbac.PermissionID{"review"},
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	authorizer, err := rbac.NewAuthorizer(
		policy,
		rbac.RoleResolverFunc(
			func(
				_ context.Context,
				subject string,
				scope rbac.Scope,
			) ([]rbac.RoleID, error) {
				if subject != "alice" || scope.TenantID != "north" {
					return nil, nil
				}

				return f.roles, nil
			},
		),
		rbac.Options{RequireTenant: true},
	)
	if err != nil {
		t.Fatal(err)
	}

	permission, err := authorizer.Require("review")
	if err != nil {
		t.Fatal(err)
	}

	resource, err := permission.WithResourcePolicy(
		rbac.ResourcePolicyFunc(
			func(_ context.Context, request rbac.Request, key string) error {
				if f.beforeResource != nil {
					f.beforeResource()
				}

				if !f.resource || request.SubjectID != "alice" ||
					request.Scope.TenantID != "north" ||
					key != "one" {
					return rbac.ErrForbidden
				}

				return nil
			},
		),
	)
	if err != nil {
		t.Fatal(err)
	}

	f.requirement = resource

	f.gate, err = identitygate.New(
		f.manager,
		resource,
		identitygate.MembershipVerifierFunc(
			func(_ context.Context, subject, tenant string) error {
				if !f.membership || subject != "alice" || tenant != "north" {
					return rbac.ErrForbidden
				}

				return nil
			},
		),
	)
	if err != nil {
		t.Fatal(err)
	}

	return f
}

func TestCurrentIdentityMembershipPermissionAndResource(t *testing.T) {
	f := setup(t)

	var escaped *identitygate.Execution

	writes := 0

	err := f.manager.WithIdentity(
		t.Context(),
		f.token,
		func(ctx context.Context, identity *auth.Identity) error {
			return f.gate.Within(
				ctx,
				identity,
				"north",
				"one",
				func(
					ctx context.Context,
					execution *identitygate.Execution,
				) error {
					escaped = execution
					if execution.SubjectID() != "alice" ||
						execution.TenantID() != "north" ||
						execution.ResourceID() != "one" {
						t.Fatal("bound facts changed")
					}

					if err := f.gate.Use(
						ctx,
						execution,
						"north",
						"one",
						func(context.Context) error { writes++; return nil },
					); err != nil {
						t.Fatal(err)
					}

					for _, binding := range [][2]string{
						{
							"south",
							"one",
						},
						{
							"north",
							"two",
						},
					} {
						if err := f.gate.Use(
							ctx,
							execution,
							binding[0],
							binding[1],
							func(context.Context) error {
								t.Fatal("cross-binding ran")

								return nil
							},
						); !errors.Is(
							err,
							rbac.ErrForbidden,
						) {
							t.Fatal(err)
						}
					}

					for _, disable := range []func(){
						func() { f.membership = false },
						func() { f.roles = nil },
						func() { f.resource = false },
					} {
						disable()

						if err := f.gate.Use(
							ctx,
							execution,
							"north",
							"one",
							func(context.Context) error {
								t.Fatal("stale authority ran")

								return nil
							},
						); !errors.Is(
							err,
							rbac.ErrForbidden,
						) {
							t.Fatal(err)
						}

						f.membership = true
						f.resource = true
						f.roles = []rbac.RoleID{"reviewer"}
					}

					if err := f.manager.Revoke(ctx, f.token); err != nil {
						t.Fatal(err)
					}

					return f.gate.Use(
						ctx,
						execution,
						"north",
						"one",
						func(context.Context) error {
							t.Fatal("revoked session ran")

							return nil
						},
					)
				},
			)
		},
	)
	if !errors.Is(err, auth.ErrUnauthenticated) || writes != 1 {
		t.Fatalf("err=%v writes=%d", err, writes)
	}

	if err := f.gate.Use(
		t.Context(),
		escaped,
		"north",
		"one",
		func(context.Context) error {
			t.Fatal("escaped execution ran")

			return nil
		},
	); err == nil {
		t.Fatal("escaped execution allowed")
	}
}

func TestZeroForeignIdentityAndDeniedResource(t *testing.T) {
	f := setup(t)
	for _, identity := range []*auth.Identity{nil, {}} {
		if err := f.gate.Within(
			t.Context(),
			identity,
			"north",
			"one",
			func(context.Context, *identitygate.Execution) error {
				t.Fatal("zero identity ran")

				return nil
			},
		); err == nil {
			t.Fatal("zero identity allowed")
		}
	}

	foreign := newManager(t)

	issued, err := foreign.Start(t.Context(), "alice")
	if err != nil {
		t.Fatal(err)
	}

	err = foreign.WithIdentity(
		t.Context(),
		issued.Token,
		func(ctx context.Context, identity *auth.Identity) error {
			return f.gate.Within(
				ctx,
				identity,
				"north",
				"one",
				func(context.Context, *identitygate.Execution) error {
					t.Fatal("foreign issuer ran")

					return nil
				},
			)
		},
	)
	if !errors.Is(err, auth.ErrUnauthenticated) {
		t.Fatal(err)
	}

	f.resource = false

	err = f.manager.WithIdentity(
		t.Context(),
		f.token,
		func(ctx context.Context, identity *auth.Identity) error {
			return f.gate.Within(
				ctx,
				identity,
				"north",
				"one",
				func(context.Context, *identitygate.Execution) error {
					t.Fatal("denied resource ran")

					return nil
				},
			)
		},
	)
	if !errors.Is(err, rbac.ErrForbidden) {
		t.Fatal(err)
	}
}

func TestOriginalCancellationDuringResourcePolicy(t *testing.T) {
	for _, duringUse := range []bool{false, true} {
		f := setup(t)
		original, cancel := context.WithCancel(t.Context())
		err := f.manager.WithIdentity(
			original,
			f.token,
			func(_ context.Context, identity *auth.Identity) error {
				if !duringUse {
					f.beforeResource = cancel
				}

				return f.gate.Within(
					context.Background(),
					identity,
					"north",
					"one",
					func(
						ctx context.Context,
						execution *identitygate.Execution,
					) error {
						if !duringUse {
							t.Fatal(
								"cancellation during entry policy " +
									"reached operation",
							)
						}

						f.beforeResource = cancel

						return f.gate.Use(
							ctx,
							execution,
							"north",
							"one",
							func(context.Context) error {
								t.Fatal(
									"cancellation during use " +
										"policy reached write",
								)

								return nil
							},
						)
					},
				)
			},
		)

		cancel()

		if !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
	}
}

type mapMembership map[string]bool

func (mapMembership) VerifyMembership(
	context.Context,
	string,
	string,
) error {
	return nil
}

type sliceMembership []string

func (sliceMembership) VerifyMembership(
	context.Context,
	string,
	string,
) error {
	return nil
}

type channelMembership chan struct{}

func (channelMembership) VerifyMembership(
	context.Context,
	string,
	string,
) error {
	return nil
}

func TestNilMembershipDependenciesDeny(t *testing.T) {
	f := setup(t)
	for _, membership := range []identitygate.MembershipVerifier{
		nil,
		mapMembership(nil),
		sliceMembership(nil),
		channelMembership(nil),
		identitygate.MembershipVerifierFunc(nil),
	} {
		if gate, err := identitygate.New(
			f.manager,
			f.requirement,
			membership,
		); !errors.Is(err, rbac.ErrUnconfigured) ||
			gate != nil {
			t.Fatalf("nil membership accepted: gate=%v error=%v", gate, err)
		}
	}

	for _, membership := range []identitygate.MembershipVerifier{
		mapMembership{}, sliceMembership{}, make(channelMembership),
	} {
		gate, err := identitygate.New(f.manager, f.requirement, membership)
		if err != nil {
			t.Fatal(err)
		}

		calls := 0

		err = f.manager.WithIdentity(
			t.Context(),
			f.token,
			func(ctx context.Context, identity *auth.Identity) error {
				return gate.Within(
					ctx,
					identity,
					"north",
					"one",
					func(context.Context, *identitygate.Execution) error {
						calls++
						return nil
					},
				)
			},
		)
		if err != nil || calls != 1 {
			t.Fatalf("valid membership rejected: calls=%d error=%v", calls, err)
		}
	}
}
