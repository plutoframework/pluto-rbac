package rbac_test

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	rbac "github.com/plutoframework/pluto-rbac"
)

func TestExecutionOriginalCancellationReachesActiveUse(t *testing.T) {
	for _, stage := range []string{"lookup", "callback"} {
		t.Run(stage, func(t *testing.T) {
			var block atomic.Bool

			started := make(chan struct{})
			resolver := rbac.RoleResolverFunc(
				func(
					ctx context.Context,
					_ string,
					_ rbac.Scope,
				) ([]rbac.RoleID, error) {
					if block.Load() {
						close(started)
						<-ctx.Done()

						return nil, ctx.Err()
					}

					return []rbac.RoleID{admin}, nil
				},
			)

			required, err := newAuthorizer(t, resolver, false).Require(manage)
			if err != nil {
				t.Fatal(err)
			}

			original, cancelOriginal := context.WithCancel(t.Context())
			defer cancelOriginal()

			independent, cancelUse := context.WithCancel(context.Background())
			defer cancelUse()

			done := make(chan error, 1)
			go func() {
				done <- required.Within(
					original,
					"alice",
					rbac.Scope{},
					"record:1",
					func(_ context.Context, execution *rbac.Execution) error {
						block.Store(stage == "lookup")

						return required.Use(
							independent,
							execution,
							"alice",
							rbac.Scope{},
							"record:1",
							func(ctx context.Context) error {
								close(started)
								<-ctx.Done()

								return ctx.Err()
							},
						)
					},
				)
			}()

			select {
			case <-started:
			case <-time.After(2 * time.Second):
				cancelUse()
				t.Fatal("use did not reach blocking dependency")
			}

			cancelOriginal()

			select {
			case err := <-done:
				if !errors.Is(err, context.Canceled) {
					t.Fatalf("canceled active use returned %v", err)
				}
			case <-time.After(time.Second):
				cancelUse()
				<-done
				t.Fatal("original cancellation did not release active use")
			}
		})
	}
}
