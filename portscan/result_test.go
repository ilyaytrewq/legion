package portscan

import (
	"errors"
	"net"
	"testing"
	"time"
)

func TestResultString(t *testing.T) {
	tests := []struct {
		name   string
		result Result
		want   string
	}{
		{
			name: "open literal target",
			result: Result{
				Host: "127.0.0.1", IP: net.ParseIP("127.0.0.1"), Port: 80,
				State: StateOpen, Duration: 1500 * time.Microsecond,
			},
			want: "127.0.0.1:80 open (1.5ms)",
		},
		{
			name: "name target shows the address it resolved to",
			result: Result{
				Host: "example.com", IP: net.ParseIP("93.184.216.34"), Port: 443,
				State: StateOpen, Duration: 12 * time.Millisecond,
			},
			want: "example.com (93.184.216.34):443 open (12ms)",
		},
		{
			name: "IPv6 literal is bracketed",
			result: Result{
				Host: "2001:db8::1", IP: net.ParseIP("2001:db8::1"), Port: 443,
				State: StateOpen,
			},
			want: "[2001:db8::1]:443 open",
		},
		{
			name: "scoped IPv6 literal includes zone",
			result: Result{
				Host: "fe80::1%en0", IP: net.ParseIP("fe80::1"), Zone: "en0", Port: 80,
				State: StateOpen,
			},
			want: "[fe80::1%en0]:80 open",
		},
		{
			name: "name target shows scoped IPv6 address",
			result: Result{
				Host: "link.example.com", IP: net.ParseIP("fe80::1"), Zone: "en0", Port: 80,
				State: StateOpen,
			},
			want: "link.example.com ([fe80::1%en0]):80 open",
		},
		{
			name: "closed carries the error",
			result: Result{
				Host: "127.0.0.1", IP: net.ParseIP("127.0.0.1"), Port: 81,
				State: StateClosed, Duration: 100 * time.Microsecond,
				Err: errors.New("connect: connection refused"),
			},
			want: "127.0.0.1:81 closed (100µs): connect: connection refused",
		},
		{
			name: "unresolved keeps requested port but has no address",
			result: Result{
				Host: "nx.invalid", Port: 443, State: StateUnresolved,
				Err: &TargetError{Target: "nx.invalid", Err: errors.New("no such host")},
			},
			want: `nx.invalid:443 unresolved: portscan: target "nx.invalid": no such host`,
		},
		{
			name:   "zero value",
			result: Result{},
			want:   " unknown",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.result.String(); got != tt.want {
				t.Errorf("String() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestTargetErrorUnwrap(t *testing.T) {
	dnsErr := &net.DNSError{Err: "no such host", Name: "nx.invalid", IsNotFound: true}
	err := error(&TargetError{Target: "nx.invalid", Err: dnsErr})

	joined := errors.Join(errors.New("other"), err)

	var target *TargetError
	if !errors.As(joined, &target) {
		t.Fatal("errors.As could not find *TargetError in a joined error")
	}
	if target.Target != "nx.invalid" {
		t.Errorf("Target = %q, want %q", target.Target, "nx.invalid")
	}
	var lookupErr *net.DNSError
	if !errors.As(joined, &lookupErr) {
		t.Fatal("errors.As could not reach *net.DNSError through *TargetError")
	}
	if !lookupErr.IsNotFound {
		t.Error("recovered DNSError lost IsNotFound")
	}
}
