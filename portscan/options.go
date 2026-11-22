package portscan

import (
	"context"
	"fmt"
	"net"
	"time"
)

// Dialer establishes TCP connections for a scan. It must support concurrent
// calls and return promptly when the context ends. The scanner closes any
// non-nil connection returned by DialContext, including on error.
type Dialer interface {
	DialContext(ctx context.Context, network, address string) (net.Conn, error)
}

// Resolver turns a DNS name into addresses. It must support concurrent calls
// and return promptly when the context ends.
type Resolver interface {
	LookupIPAddr(ctx context.Context, host string) ([]net.IPAddr, error)
}

const (
	maxConcurrency = 4096

	defaultConcurrency = 100

	defaultConnectTimeout = 2 * time.Second
)

type config struct {
	concurrency    int
	connectTimeout time.Duration
	firstAddrOnly  bool
	dialer         Dialer
	resolver       Resolver
}

// Option configures a Scanner.
type Option func(*config) error

// WithConcurrency limits how many connect attempts may be in flight at once.
func WithConcurrency(n int) Option {
	return func(c *config) error {
		if n < 1 || n > maxConcurrency {
			return fmt.Errorf("portscan: concurrency must be in [1, %d], got %d", maxConcurrency, n)
		}
		c.concurrency = n
		return nil
	}
}

// WithConnectTimeout sets the budget for one TCP attempt. It does not include
// resolution or waiting for a connection slot.
func WithConnectTimeout(d time.Duration) Option {
	return func(c *config) error {
		if d <= 0 {
			return fmt.Errorf("portscan: connect timeout must be positive, got %s", d)
		}
		c.connectTimeout = d
		return nil
	}
}

// WithFirstAddrOnly limits a resolved DNS name to its first usable address.
func WithFirstAddrOnly() Option {
	return func(c *config) error {
		c.firstAddrOnly = true
		return nil
	}
}

// WithDialer replaces the dialer used for connect attempts.
func WithDialer(d Dialer) Option {
	return func(c *config) error {
		if isNilInterface(d) {
			return fmt.Errorf("portscan: nil dialer")
		}
		c.dialer = d
		return nil
	}
}

// WithResolver replaces the resolver used for DNS names.
func WithResolver(r Resolver) Option {
	return func(c *config) error {
		if isNilInterface(r) {
			return fmt.Errorf("portscan: nil resolver")
		}
		c.resolver = r
		return nil
	}
}
