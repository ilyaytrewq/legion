//go:build unix

package portscan

import (
	"context"
	"errors"
	"net"
	"os"
	"syscall"
	"testing"
)

func TestScanReportsPlatformStates(t *testing.T) {
	byPort := map[string]error{
		"80": os.NewSyscallError("connect", syscall.ECONNREFUSED),
		"81": os.NewSyscallError("connect", syscall.EHOSTUNREACH),
		"82": os.NewSyscallError("connect", syscall.ETIMEDOUT),
		"83": os.NewSyscallError("connect", syscall.EMFILE),
		"84": errors.New("boom"),
	}
	dialer := &fakeDialer{dial: func(_ context.Context, address string) (net.Conn, error) {
		_, port, err := net.SplitHostPort(address)
		if err != nil {
			return nil, err
		}
		return nil, opErr(byPort[port])
	}}
	scanner := mustScanner(t, WithDialer(dialer))

	results, err := scanner.ScanAll(t.Context(), []string{"192.0.2.1"}, mustPorts(t, "80-84"))
	if err != nil {
		t.Fatalf("ScanAll: %v", err)
	}
	if len(results) != 5 {
		t.Fatalf("got %d results, want 5", len(results))
	}

	want := map[uint16]State{
		80: StateClosed,
		81: StateUnreachable,
		82: StateTimeout,
		83: StateError,
		84: StateError,
	}
	for _, r := range results {
		if r.State != want[r.Port] {
			t.Errorf("port %d: State = %v, want %v (%v)", r.Port, r.State, want[r.Port], r.Err)
		}
		if r.Err == nil {
			t.Errorf("port %d: Err is nil for state %v", r.Port, r.State)
		}
		if got, want := errors.Is(r.Err, ErrResourceExhausted), r.Port == 83; got != want {
			t.Errorf("port %d: matches ErrResourceExhausted = %t, want %t (%v)",
				r.Port, got, want, r.Err)
		}
		var errno syscall.Errno
		if r.Port != 84 && !errors.As(r.Err, &errno) {
			t.Errorf("port %d: the error number is no longer reachable: %v", r.Port, r.Err)
		}
	}
}
