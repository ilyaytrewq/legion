package portscan

import (
	"context"
	"errors"
	"net"
	"time"
)

const maxResolvers = 32

var errUninitializedScanner = errors.New("portscan: scanner is not initialized; use New")

// Scanner checks TCP ports with a fixed configuration. Its zero value is not
// ready to use; construct a Scanner with [New].
type Scanner struct {
	concurrency    int
	connectTimeout time.Duration
	firstAddrOnly  bool
	dialer         Dialer
	resolver       Resolver

	sem         semaphore
	resolverSem semaphore
}

// New returns a Scanner configured by the given options.
func New(opts ...Option) (*Scanner, error) {
	cfg := config{
		concurrency:    defaultConcurrency,
		connectTimeout: defaultConnectTimeout,
		dialer:         &net.Dialer{KeepAlive: -1},
		resolver:       net.DefaultResolver,
	}
	for _, opt := range opts {
		if opt == nil {
			return nil, errNilOption
		}
		if err := opt(&cfg); err != nil {
			return nil, err
		}
	}
	return &Scanner{
		concurrency:    cfg.concurrency,
		connectTimeout: cfg.connectTimeout,
		firstAddrOnly:  cfg.firstAddrOnly,
		dialer:         cfg.dialer,
		resolver:       cfg.resolver,
		sem:            make(semaphore, cfg.concurrency),
		resolverSem:    make(semaphore, min(maxResolvers, cfg.concurrency)),
	}, nil
}

// Scan checks every port of ports on every address of hosts and streams the
// results. Identical target strings are deduplicated; distinct strings can
// produce separate results for the same IP address. CIDR targets may contain
// at most 65536 addresses. A resolution failure gets a separate [TargetError]
// per result, but the wrapped resolver error may be shared and is read-only.
//
// After checking for a nil context or an uninitialized Scanner, Scan returns
// (nil, ctx.Err()) if it observes cancellation during preflight, before
// reporting target or port validation errors.
//
// The context governs DNS lookups and connection attempts. Results arrive in
// no guaranteed order; read the channel until it closes or cancel the context
// if stopping early. On cancellation, Scan stops submitting work. Results
// from work already in progress may still arrive before the channel closes,
// but delivery is best effort: results not already received may be dropped.
func (s *Scanner) Scan(ctx context.Context, hosts []string, ports PortSet) (<-chan Result, error) {
	if ctx == nil {
		return nil, errNilContext
	}
	if s == nil || s.concurrency <= 0 || s.connectTimeout <= 0 ||
		s.dialer == nil || s.resolver == nil || s.sem == nil || s.resolverSem == nil {
		return nil, errUninitializedScanner
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if len(hosts) == 0 {
		return nil, ErrNoTargets
	}
	if ports.Len() == 0 {
		return nil, ErrNoPorts
	}
	targets, err := parseTargets(ctx, hosts)
	if ctxErr := ctx.Err(); ctxErr != nil {
		return nil, ctxErr
	}
	if err != nil {
		return nil, err
	}

	return s.run(ctx, targets, ports), nil
}

// ScanAll collects all results from [Scanner.Scan] into a slice. If the scan
// is canceled after it starts, ScanAll returns any collected results and ctx.Err().
func (s *Scanner) ScanAll(ctx context.Context, hosts []string, ports PortSet) ([]Result, error) {
	ch, err := s.Scan(ctx, hosts, ports)
	if err != nil {
		return nil, err
	}
	var out []Result
	for r := range ch {
		out = append(out, r)
	}
	return out, ctx.Err()
}
