package portscan

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"time"
)

// reachedCallerDeadline detects a net poller timeout at the caller's own
// deadline, even if the context timer has not closed Done yet.
func reachedCallerDeadline(ctx, dialCtx context.Context, finishedAt time.Time) bool {
	callerDeadline, ok := ctx.Deadline()
	if !ok || finishedAt.Before(callerDeadline) {
		return false
	}
	dialDeadline, ok := dialCtx.Deadline()
	return ok && dialDeadline.Equal(callerDeadline)
}

func classify(dialCtx context.Context, err error, callerDeadlineReached bool) State {
	if err == nil {
		return StateOpen
	}

	if state, ok := classifySyscallErr(err); ok {
		return state
	}

	if errors.Is(context.Cause(dialCtx), errConnectTimeout) {
		return StateTimeout
	}
	if dialCtx.Err() != nil {
		return StateCanceled
	}

	var netErr net.Error
	if errors.Is(err, os.ErrDeadlineExceeded) || (errors.As(err, &netErr) && netErr.Timeout()) {
		if callerDeadlineReached {
			return StateCanceled
		}
		return StateTimeout
	}

	return StateError
}

func reportErr(err error) error {
	if isResourceErr(err) {
		return fmt.Errorf("%w: %w", ErrResourceExhausted, err)
	}
	return err
}
