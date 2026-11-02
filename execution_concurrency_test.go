package rbac_test

import (
	"context"
	"errors"
	"runtime"
	"testing"
	"time"

	rbac "github.com/plutoframework/pluto-rbac"
)

func TestExecutionWaitsForActiveUses(t *testing.T) {
	resolver := rbac.RoleResolverFunc(
		func(context.Context, string, rbac.Scope) ([]rbac.RoleID, error) {
			return []rbac.RoleID{admin}, nil
		},
	)

	required, err := newAuthorizer(t, resolver, false).Require(manage)
	if err != nil {
		t.Fatal(err)
	}

	started := make(chan struct{})
	handed := make(chan *rbac.Execution, 1)
	release := make(chan struct{})
	useDone := make(chan error, 1)

	withinDone := make(chan error, 1)
	go func() {
		withinDone <- required.Within(
			context.Background(),
			"alice",
			rbac.Scope{},
			"record:1",
			func(
				ctx context.Context,
				execution *rbac.Execution,
			) error {
				go func() {
					useDone <- required.Use(
						ctx,
						execution,
						"alice",
						rbac.Scope{},
						"record:1",
						func(
							context.Context,
						) error {
							close(started)
							<-release

							return nil
						},
					)
				}()

				<-started

				handed <- execution

				return nil
			},
		)
	}()

	execution := <-handed
	deadline := time.After(5 * time.Second)

	for {
		err := required.Use(
			context.Background(),
			execution,
			"alice",
			rbac.Scope{},
			"record:1",
			func(context.Context) error { return nil },
		)
		if errors.Is(err, rbac.ErrForbidden) {
			break
		}

		if err != nil {
			t.Fatal(err)
		}

		select {
		case <-deadline:
			t.Fatal("scope did not close admission")
		default:
			runtime.Gosched()
		}
	}

	select {
	case err := <-withinDone:
		t.Fatalf("scope returned before active callback: %v", err)
	default:
	}

	close(release)

	if err := <-withinDone; err != nil {
		t.Fatal(err)
	}

	if err := <-useDone; err != nil {
		t.Fatal(err)
	}
}

func TestExecutionNestedUses(t *testing.T) {
	resolver := rbac.RoleResolverFunc(
		func(context.Context, string, rbac.Scope) ([]rbac.RoleID, error) {
			return []rbac.RoleID{admin}, nil
		},
	)

	required, err := newAuthorizer(t, resolver, false).Require(manage)
	if err != nil {
		t.Fatal(err)
	}

	err = required.Within(
		context.Background(),
		"alice",
		rbac.Scope{},
		"record:1",
		func(ctx context.Context, execution *rbac.Execution) error {
			return required.Use(
				ctx,
				execution,
				"alice",
				rbac.Scope{},
				"record:1",
				func(ctx context.Context) error {
					return required.Use(
						ctx,
						execution,
						"alice",
						rbac.Scope{},
						"record:1",
						func(context.Context) error { return nil },
					)
				},
			)
		},
	)
	if err != nil {
		t.Fatal(err)
	}
}
