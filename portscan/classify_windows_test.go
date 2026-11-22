//go:build windows

package portscan

import (
	"errors"
	"os"
	"syscall"
	"testing"
)

func TestClassifyErrnoWindows(t *testing.T) {
	tests := []struct {
		name  string
		errno syscall.Errno
		want  State
	}{
		{"connection refused", wsaeconnrefused, StateClosed},
		{"connection reset", wsaeconnreset, StateError},

		{"host unreachable", wsaehostunreach, StateUnreachable},
		{"network unreachable", wsaenetunreach, StateUnreachable},
		{"host down", wsaehostdown, StateUnreachable},
		{"network down", wsaenetdown, StateUnreachable},
		{"access denied", wsaeaccess, StateError},

		{"timed out", wsaetimedout, StateTimeout},

		{"too many open sockets", wsaemfile, StateError},
		{"no buffer space", wsaenobufs, StateError},
		{"no ephemeral port left", wsaeaddrnotavail, StateError},

		{"address family unsupported", wsaeafnosupport, StateError},
		{"connection aborted", wsaeconnaborted, StateError},
		{"network reset", wsaenetreset, StateError},
		{"wrong protocol type", wsaeprototype, StateError},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := opErr(os.NewSyscallError("connectex", tt.errno))
			if got := classify(liveDialCtx(t), err, false); got != tt.want {
				t.Errorf("classify(%v) = %v, want %v", err, got, tt.want)
			}
		})
	}
}

func TestWinsockNumbersAreTheRealOnes(t *testing.T) {
	if wsaeconnrefused == syscall.ECONNREFUSED {
		t.Fatal("wsaeconnrefused equals syscall.ECONNREFUSED; the placeholder assumption no longer holds")
	}
	err := opErr(os.NewSyscallError("connectex", syscall.ECONNREFUSED))
	if got := classify(liveDialCtx(t), err, false); got == StateClosed {
		t.Error("the placeholder syscall.ECONNREFUSED was classified as closed")
	}
}

func TestClassifyErrnoOutranksContextWindows(t *testing.T) {
	err := opErr(os.NewSyscallError("connectex", wsaeconnrefused))
	if got := classify(expiredDialCtx(t), err, false); got != StateClosed {
		t.Errorf("with an expired attempt context: %v, want %v", got, StateClosed)
	}
	if got := classify(canceledDialCtx(t), err, false); got != StateClosed {
		t.Errorf("with a cancelled scan context: %v, want %v", got, StateClosed)
	}
}

func TestReportErrResourceExhaustionWindows(t *testing.T) {
	for _, errno := range []syscall.Errno{wsaemfile, wsaenobufs} {
		err := opErr(os.NewSyscallError("connectex", errno))
		got := reportErr(err)
		if !errors.Is(got, ErrResourceExhausted) {
			t.Errorf("reportErr(%v) does not match ErrResourceExhausted", errno)
		}
		if !errors.Is(got, errno) {
			t.Errorf("reportErr(%v) lost the underlying error number", errno)
		}
	}
	err := opErr(os.NewSyscallError("connectex", wsaeconnrefused))
	if errors.Is(reportErr(err), ErrResourceExhausted) {
		t.Error("a refused connection was reported as resource exhaustion")
	}
	err = opErr(os.NewSyscallError("connectex", wsaeaddrnotavail))
	if errors.Is(reportErr(err), ErrResourceExhausted) {
		t.Error("an unavailable local address was reported as resource exhaustion")
	}
}
