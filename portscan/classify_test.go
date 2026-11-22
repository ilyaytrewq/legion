package portscan

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"testing"
	"time"
)

func liveDialCtx(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeoutCause(context.Background(), time.Hour, errConnectTimeout)
	t.Cleanup(cancel)
	return ctx
}

func expiredDialCtx(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeoutCause(context.Background(), time.Nanosecond, errConnectTimeout)
	t.Cleanup(cancel)
	<-ctx.Done()
	return ctx
}

func canceledDialCtx(t *testing.T) context.Context {
	t.Helper()
	parent, cancelParent := context.WithCancel(context.Background())
	ctx, cancel := context.WithTimeoutCause(parent, time.Hour, errConnectTimeout)
	t.Cleanup(cancel)
	cancelParent()
	<-ctx.Done()
	return ctx
}

func deadlinedDialCtx(t *testing.T) context.Context {
	t.Helper()
	parent, cancelParent := context.WithTimeout(context.Background(), time.Nanosecond)
	t.Cleanup(cancelParent)
	ctx, cancel := context.WithTimeoutCause(parent, time.Hour, errConnectTimeout)
	t.Cleanup(cancel)
	<-ctx.Done()
	return ctx
}

func customCanceledDialCtx(t *testing.T) context.Context {
	t.Helper()
	parent, cancelParent := context.WithCancelCause(context.Background())
	ctx, cancel := context.WithTimeoutCause(parent, time.Hour, errConnectTimeout)
	t.Cleanup(cancel)
	cancelParent(errors.New("operator requested shutdown"))
	<-ctx.Done()
	return ctx
}

func customDeadlinedDialCtx(t *testing.T) context.Context {
	t.Helper()
	parent, cancelParent := context.WithTimeoutCause(
		context.Background(), time.Nanosecond, errors.New("scan budget exhausted"),
	)
	t.Cleanup(cancelParent)
	ctx, cancel := context.WithTimeoutCause(parent, time.Hour, errConnectTimeout)
	t.Cleanup(cancel)
	<-ctx.Done()
	return ctx
}

func TestClassify(t *testing.T) {
	tests := []struct {
		name string
		err  error
		ctx  func(*testing.T) context.Context
		want State
	}{
		{
			name: "handshake completed",
			err:  nil,
			ctx:  liveDialCtx,
			want: StateOpen,
		},
		{
			name: "own timeout, poller won the race",
			err:  opErr(os.ErrDeadlineExceeded),
			ctx:  expiredDialCtx,
			want: StateTimeout,
		},
		{
			name: "own timeout, context won the race",
			err:  opErr(context.DeadlineExceeded),
			ctx:  expiredDialCtx,
			want: StateTimeout,
		},
		{
			name: "kernel timeout with no deadline involved",
			err:  opErr(os.ErrDeadlineExceeded),
			ctx:  liveDialCtx,
			want: StateTimeout,
		},
		{
			name: "scan cancelled",
			err:  opErr(context.Canceled),
			ctx:  canceledDialCtx,
			want: StateCanceled,
		},
		{
			name: "scan deadline reached",
			err:  opErr(context.DeadlineExceeded),
			ctx:  deadlinedDialCtx,
			want: StateCanceled,
		},
		{
			name: "scan cancelled with a custom cause",
			err:  opErr(context.Canceled),
			ctx:  customCanceledDialCtx,
			want: StateCanceled,
		},
		{
			name: "scan deadline reached with a custom cause",
			err:  opErr(context.DeadlineExceeded),
			ctx:  customDeadlinedDialCtx,
			want: StateCanceled,
		},
		{
			name: "dialer unexpectedly returns a DNS error",
			err:  &net.DNSError{Err: "no such host", Name: "nx.invalid", IsNotFound: true},
			ctx:  liveDialCtx,
			want: StateError,
		},
		{
			name: "unrecognised failure",
			err:  opErr(errors.New("boom")),
			ctx:  liveDialCtx,
			want: StateError,
		},
		{
			name: "unrecognised failure, wrapped further",
			err:  fmt.Errorf("scanning: %w", opErr(errors.New("boom"))),
			ctx:  liveDialCtx,
			want: StateError,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := classify(tt.ctx(t), tt.err, false); got != tt.want {
				t.Errorf("classify(%v) = %v, want %v", tt.err, got, tt.want)
			}
		})
	}
}

func TestClassifyPollerTimeoutAtCallerDeadline(t *testing.T) {
	deadline := time.Now().Add(time.Hour)
	ctx, cancel := context.WithDeadline(t.Context(), deadline)
	defer cancel()
	callerLimited, cancelDial := context.WithTimeoutCause(ctx, 2*time.Hour, errConnectTimeout)
	defer cancelDial()
	attemptLimited, cancelShort := context.WithTimeoutCause(ctx, time.Minute, errConnectTimeout)
	defer cancelShort()

	// Model the clock seen by the poller without letting the caller's context
	// timer publish its cancellation, so this test never races real timers.
	err := opErr(os.ErrDeadlineExceeded)
	for _, tt := range []struct {
		name string
		dial context.Context
		at   time.Time
		want State
	}{
		{"at caller deadline", callerLimited, deadline, StateCanceled},
		{"before caller deadline", callerLimited, deadline.Add(-time.Nanosecond), StateTimeout},
		{"attempt has an earlier deadline", attemptLimited, deadline, StateTimeout},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if got := classify(tt.dial, err, reachedCallerDeadline(ctx, tt.dial, tt.at)); got != tt.want {
				t.Errorf("classify poller timeout = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestClassifyBeforeCancelMatters(t *testing.T) {
	ctx, cancel := context.WithTimeoutCause(context.Background(), time.Nanosecond, errConnectTimeout)
	<-ctx.Done()
	err := opErr(context.DeadlineExceeded)

	if got := classify(ctx, err, false); got != StateTimeout {
		t.Fatalf("classify before cancel = %v, want %v", got, StateTimeout)
	}
	cancel()
	if got := classify(ctx, err, false); got != StateTimeout {
		t.Errorf("classify after cancel = %v, want %v: the cause of an "+
			"already-expired context must not change", got, StateTimeout)
	}
}

func TestReportErrLeavesOrdinaryErrorsAlone(t *testing.T) {
	err := opErr(errors.New("boom"))
	if got := reportErr(err); got != err { //nolint:errorlint
		t.Errorf("reportErr rewrote an ordinary error: %v", got)
	}
	if errors.Is(reportErr(err), ErrResourceExhausted) {
		t.Error("an ordinary error was reported as resource exhaustion")
	}
}
