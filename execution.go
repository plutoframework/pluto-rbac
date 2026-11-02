package rbac

import (
	"context"
	"sync"
)

// Execution is a callback-lifetime permission capability. Its zero value
// denies. Copies share lifetime state: retaining or copying it cannot extend
// the grant. It does not verify identity, resource ownership or transaction
// consistency.
type Execution struct {
	state *executionState
}

type executionState struct {
	requirement *Requirement
	subjectID   string
	scope       Scope
	resourceID  string
	context     context.Context
	mutex       sync.Mutex
	closed      *sync.Cond
	active      bool
	uses        int
}

// Within resolves permission before supplying a capability to run. resourceID
// is an exact nonempty application binding, not a resource-ownership check.
// Callers must obtain subject and scope from trusted wiring and choose the
// resource key. The capability stops admitting uses when run returns or panics;
// Within waits for admitted Use callbacks before returning or propagating that
// panic.
func (r *Requirement) Within(
	ctx context.Context,
	subjectID string,
	scope Scope,
	resourceID string,
	run func(context.Context, *Execution) error,
) error {
	if r == nil || r.authorizer == nil {
		return ErrUnconfigured
	}

	if run == nil || !validText(resourceID) {
		return ErrInvalidRequest
	}

	return r.Execute(ctx, subjectID, scope, func(ctx context.Context) error {
		state := &executionState{
			requirement: r,
			subjectID:   subjectID,
			scope:       scope,
			resourceID:  resourceID,
			context:     ctx,
			active:      true,
		}

		state.closed = sync.NewCond(&state.mutex)
		defer state.close()

		return run(ctx, &Execution{state: state})
	})
}

func (s *executionState) close() {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	s.active = false
	for s.uses > 0 {
		s.closed.Wait()
	}
}

func (s *executionState) finish() {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	s.uses--
	s.closed.Broadcast()
}

// Use validates the exact live requirement, subject, scope and resource
// binding, resolves roles again, then invokes run. A restricted adapter must
// expose this guarded invocation rather than a separate check followed by an
// exposed write. Nested synchronous Use calls are supported. A nil callback is
// invalid.
//
// The original context must remain uncanceled even when a different context is
// supplied. Use cannot prove that run's resource query matches the binding or
// make permission resolution atomic with effects. The application owns resource
// policy, transactions and restrictions on independent SQL/write entry points.
func (r *Requirement) Use(
	ctx context.Context,
	execution *Execution,
	subjectID string,
	scope Scope,
	resourceID string,
	run func(context.Context) error,
) error {
	if r == nil || r.authorizer == nil {
		return ErrUnconfigured
	}

	if ctx == nil || run == nil {
		return ErrInvalidRequest
	}

	if execution == nil || execution.state == nil {
		return ErrForbidden
	}

	state := execution.state
	state.mutex.Lock()

	if state.requirement != r || state.subjectID != subjectID ||
		state.scope != scope || state.resourceID != resourceID ||
		!state.active {
		state.mutex.Unlock()

		return ErrForbidden
	}

	state.uses++

	state.mutex.Unlock()
	defer state.finish()

	// Keep values from the use context and cancellation from both scopes.
	ctx, cancel := context.WithCancel(ctx)

	stop := context.AfterFunc(state.context, cancel)
	defer cancel()
	defer stop()

	if err := state.context.Err(); err != nil {
		return err
	}

	if err := r.authorizer.Authorize(ctx, Request{
		SubjectID:  subjectID,
		Scope:      scope,
		Permission: r.permission,
	}); err != nil {
		return err
	}

	state.mutex.Lock()

	active := state.active
	state.mutex.Unlock()

	if !active {
		return ErrForbidden
	}

	if err := state.context.Err(); err != nil {
		return err
	}

	if err := ctx.Err(); err != nil {
		return err
	}

	return run(ctx)
}
