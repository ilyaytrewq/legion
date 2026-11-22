package portscan

import (
	"context"
	"net"
	"os"
	"slices"
	"sync"
	"testing"
)

type fakeConn struct {
	net.Conn
	mu     sync.Mutex
	closed bool
}

func (c *fakeConn) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.closed = true
	return nil
}

func (c *fakeConn) isClosed() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.closed
}

type fakeDialer struct {
	dial func(ctx context.Context, address string) (net.Conn, error)

	mu       sync.Mutex
	inFlight int
	peak     int
	dialed   []string
	conns    []*fakeConn
}

func (d *fakeDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	d.enter(address)
	defer d.leave()
	if d.dial == nil {
		return d.openConn(), nil
	}
	return d.dial(ctx, address)
}

func (d *fakeDialer) enter(address string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.inFlight++
	d.peak = max(d.peak, d.inFlight)
	d.dialed = append(d.dialed, address)
}

func (d *fakeDialer) leave() {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.inFlight--
}

func (d *fakeDialer) openConn() *fakeConn {
	conn := &fakeConn{}
	d.mu.Lock()
	defer d.mu.Unlock()
	d.conns = append(d.conns, conn)
	return conn
}

func (d *fakeDialer) peakInFlight() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.peak
}

func (d *fakeDialer) attempts() []string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return slices.Clone(d.dialed)
}

func (d *fakeDialer) assertAllConnsClosed(t *testing.T) {
	t.Helper()
	d.mu.Lock()
	conns := slices.Clone(d.conns)
	d.mu.Unlock()
	for i, conn := range conns {
		if !conn.isClosed() {
			t.Errorf("connection %d of %d was never closed", i, len(conns))
		}
	}
}

type fakeResolver struct {
	addrs map[string][]net.IPAddr
	err   error
	hook  func(ctx context.Context, host string) error

	mu   sync.Mutex
	seen []string
}

func newFakeResolver(table map[string][]string) *fakeResolver {
	addrs := make(map[string][]net.IPAddr, len(table))
	for host, ips := range table {
		for _, ip := range ips {
			addrs[host] = append(addrs[host], net.IPAddr{IP: net.ParseIP(ip)})
		}
		if addrs[host] == nil {
			addrs[host] = []net.IPAddr{}
		}
	}
	return &fakeResolver{addrs: addrs}
}

func (r *fakeResolver) LookupIPAddr(ctx context.Context, host string) ([]net.IPAddr, error) {
	r.mu.Lock()
	r.seen = append(r.seen, host)
	r.mu.Unlock()

	if r.hook != nil {
		if err := r.hook(ctx, host); err != nil {
			return nil, err
		}
	}
	if r.err != nil {
		return nil, r.err
	}
	addrs, ok := r.addrs[host]
	if !ok {
		return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
	}
	return slices.Clone(addrs), nil
}

func (r *fakeResolver) lookups() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return slices.Clone(r.seen)
}

func opErr(err error) error {
	return &net.OpError{Op: "dial", Net: "tcp", Err: err}
}

func blockUntilDeadline(ctx context.Context, _ string) (net.Conn, error) {
	<-ctx.Done()
	return nil, opErr(os.ErrDeadlineExceeded)
}
