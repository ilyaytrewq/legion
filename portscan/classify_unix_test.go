//go:build unix

package portscan

import (
	"errors"
	"os"
	"syscall"
	"testing"
)

func TestClassifyErrnoUnix(t *testing.T) {
	tests := []struct {
		name  string
		errno syscall.Errno
		want  State
	}{
		{"connection refused", syscall.ECONNREFUSED, StateClosed},
		{"connection reset", syscall.ECONNRESET, StateError},

		{"host unreachable", syscall.EHOSTUNREACH, StateUnreachable},
		{"network unreachable", syscall.ENETUNREACH, StateUnreachable},
		{"host down", syscall.EHOSTDOWN, StateUnreachable},
		{"network down", syscall.ENETDOWN, StateUnreachable},
		{"access denied", syscall.EACCES, StateError},
		{"not permitted", syscall.EPERM, StateError},

		{"SYN retries exhausted", syscall.ETIMEDOUT, StateTimeout},

		{"too many open files", syscall.EMFILE, StateError},
		{"file table overflow", syscall.ENFILE, StateError},
		{"no buffer space", syscall.ENOBUFS, StateError},
		{"out of memory", syscall.ENOMEM, StateError},
		{"no ephemeral port left", syscall.EADDRNOTAVAIL, StateError},
		{"would block", syscall.EAGAIN, StateError},

		{"address family unsupported", syscall.EAFNOSUPPORT, StateError},
		{"connection aborted", syscall.ECONNABORTED, StateError},
		{"network reset", syscall.ENETRESET, StateError},
		{"wrong protocol type", syscall.EPROTOTYPE, StateError},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := opErr(os.NewSyscallError("connect", tt.errno))
			if got := classify(liveDialCtx(t), err, false); got != tt.want {
				t.Errorf("classify(%v) = %v, want %v", err, got, tt.want)
			}
		})
	}
}

func TestClassifyErrnoOutranksContextUnix(t *testing.T) {
	err := opErr(os.NewSyscallError("connect", syscall.ECONNREFUSED))
	if got := classify(expiredDialCtx(t), err, false); got != StateClosed {
		t.Errorf("with an expired attempt context: %v, want %v", got, StateClosed)
	}
	if got := classify(canceledDialCtx(t), err, false); got != StateClosed {
		t.Errorf("with a cancelled scan context: %v, want %v", got, StateClosed)
	}
	if got := classify(deadlinedDialCtx(t), err, false); got != StateClosed {
		t.Errorf("with an expired scan context: %v, want %v", got, StateClosed)
	}
}

func TestClassifyUnknownErrnoUnix(t *testing.T) {
	err := opErr(os.NewSyscallError("connect", syscall.ENOSYS))
	if got := classify(liveDialCtx(t), err, false); got != StateError {
		t.Errorf("classify(%v) = %v, want %v", err, got, StateError)
	}
}

func TestReportErrResourceExhaustionUnix(t *testing.T) {
	for _, errno := range []syscall.Errno{
		syscall.EMFILE, syscall.ENFILE, syscall.ENOBUFS, syscall.ENOMEM,
		syscall.EAGAIN,
	} {
		err := opErr(os.NewSyscallError("connect", errno))
		got := reportErr(err)
		if !errors.Is(got, ErrResourceExhausted) {
			t.Errorf("reportErr(%v) does not match ErrResourceExhausted", errno)
		}
		if !errors.Is(got, errno) {
			t.Errorf("reportErr(%v) lost the underlying error number", errno)
		}
	}
	err := opErr(os.NewSyscallError("connect", syscall.ECONNREFUSED))
	if errors.Is(reportErr(err), ErrResourceExhausted) {
		t.Error("a refused connection was reported as resource exhaustion")
	}
	err = opErr(os.NewSyscallError("connect", syscall.EADDRNOTAVAIL))
	if errors.Is(reportErr(err), ErrResourceExhausted) {
		t.Error("an unavailable local address was reported as resource exhaustion")
	}
}
