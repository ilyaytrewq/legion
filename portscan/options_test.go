package portscan

import (
	"fmt"
	"net"
	"testing"
)

func TestNewRejectsTypedNilDependencies(t *testing.T) {
	var (
		dialer   *net.Dialer
		resolver *net.Resolver
	)
	tests := []struct {
		name string
		opt  Option
	}{
		{name: "dialer", opt: WithDialer(dialer)},
		{name: "resolver", opt: WithResolver(resolver)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			scanner, err := New(tt.opt)
			if err == nil {
				t.Fatal("New succeeded, want an error")
			}
			if scanner != nil {
				t.Error("New returned a Scanner together with an error")
			}
		})
	}
}

func TestWithConcurrencyBounds(t *testing.T) {
	if _, err := New(WithConcurrency(maxConcurrency)); err != nil {
		t.Fatalf("New with maximum concurrency: %v", err)
	}
	if scanner, err := New(WithConcurrency(maxConcurrency + 1)); err == nil || scanner != nil {
		t.Fatalf("New above maximum = (%v, %v), want (nil, error)", scanner, err)
	}
}

func TestResolverBudgetFollowsConcurrency(t *testing.T) {
	for _, concurrency := range []int{1, 17, maxResolvers, defaultConcurrency, maxConcurrency} {
		t.Run(fmt.Sprintf("concurrency_%d", concurrency), func(t *testing.T) {
			scanner, err := New(WithConcurrency(concurrency))
			if err != nil {
				t.Fatalf("New: %v", err)
			}
			if want := min(maxResolvers, concurrency); cap(scanner.resolverSem) != want {
				t.Errorf("resolver budget = %d, want %d", cap(scanner.resolverSem), want)
			}
		})
	}
}
