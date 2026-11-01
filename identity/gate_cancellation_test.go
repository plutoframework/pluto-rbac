package identitygate_test

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	identitygate "github.com/plutoframework/pluto-rbac/identity"

	auth "github.com/plutoframework/pluto-auth"
)

func TestOperationCancellationReachesMembership(t *testing.T) {
	f := setup(t)

	operation, cancelOperation := context.WithCancel(t.Context())
	defer cancelOperation()

	started := make(chan struct{})
	release := make(chan struct{})

	var (
		block atomic.Bool
		wrote atomic.Bool
	)

	gate, err := identitygate.New(
		f.manager,
		f.requirement,
		identitygate.MembershipVerifierFunc(
			func(ctx context.Context, _, _ string) error {
				if !block.Load() {
					return nil
				}

				close(started)

				select {
				case <-ctx.Done():
					return ctx.Err()
				case <-release:
					return errors.New("test cleanup released verifier")
				}
			},
		),
	)
	if err != nil {
		t.Fatal(err)
	}

	done := make(chan error, 1)
	go func() {
		done <- f.manager.WithIdentity(
			t.Context(),
			f.token,
			func(_ context.Context, identity *auth.Identity) error {
				result := gate.Within(
					operation,
					identity,
					"north",
					"one",
					func(
						_ context.Context,
						execution *identitygate.Execution,
					) error {
						block.Store(true)

						return gate.Use(
							context.Background(),
							execution,
							"north",
							"one",
							func(context.Context) error {
								wrote.Store(true)

								return nil
							},
						)
					},
				)

				// Only the operation was canceled; its separately issued
				// identity stays live.
				if err := f.manager.UseIdentity(
					context.Background(),
					identity,
					func(context.Context, string) error {
						return nil
					},
				); err != nil {
					return errors.New("issuing identity unexpectedly canceled")
				}

				return result
			},
		)
	}()

	select {
	case <-started:
	case err := <-done:
		t.Fatalf("gate failed before membership lookup: %v", err)
	case <-time.After(2 * time.Second):
		close(release)
		t.Fatal("use did not reach membership verifier")
	}

	cancelOperation()

	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("canceled membership returned %v", err)
		}
	case <-time.After(time.Second):
		close(release)
		<-done
		t.Fatal("operation cancellation did not release membership lookup")
	}

	if wrote.Load() {
		t.Fatal("canceled membership lookup reached write callback")
	}
}

func TestOperationContextCheckedBeforeMembership(t *testing.T) {
	for _, canceled := range []bool{false, true} {
		t.Run(map[bool]string{false: "live", true: "canceled"}[canceled],
			func(t *testing.T) {
				f := setup(t)

				operation, cancel := context.WithCancel(t.Context())
				defer cancel()

				checks, writes := 0, 0

				gate, err := identitygate.New(
					f.manager,
					f.requirement,
					identitygate.MembershipVerifierFunc(
						func(context.Context, string, string) error {
							checks++

							return nil
						},
					),
				)
				if err != nil {
					t.Fatal(err)
				}

				err = f.manager.WithIdentity(
					t.Context(),
					f.token,
					func(_ context.Context, identity *auth.Identity) error {
						return gate.Within(
							operation, identity, "north", "one",
							func(
								_ context.Context,
								execution *identitygate.Execution,
							) error {
								if canceled {
									cancel()
								}

								return gate.Use(
									context.Background(),
									execution, "north", "one",
									func(context.Context) error {
										writes++

										return nil
									},
								)
							},
						)
					},
				)
				if canceled {
					if !errors.Is(err, context.Canceled) ||
						checks != 1 || writes != 0 {
						t.Fatalf(
							"err=%v checks=%d writes=%d",
							err,
							checks,
							writes,
						)
					}
				} else if err != nil || checks != 2 || writes != 1 {
					t.Fatalf("err=%v checks=%d writes=%d", err, checks, writes)
				}
			},
		)
	}
}
