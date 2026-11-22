package portscan

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"slices"
	"strconv"
	"strings"
	"testing"
	"testing/synctest"
	"time"
)

func mustPorts(t *testing.T, spec string) PortSet {
	t.Helper()
	ports, err := ParsePorts(spec)
	if err != nil {
		t.Fatalf("ParsePorts(%q): %v", spec, err)
	}
	return ports
}

func mustScanner(t *testing.T, opts ...Option) *Scanner {
	t.Helper()
	scanner, err := New(opts...)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return scanner
}

func drain(t *testing.T, ch <-chan Result) []Result {
	t.Helper()
	var out []Result
	for r := range ch {
		out = append(out, r)
	}
	return out
}

type observingConn struct {
	net.Conn
	onClose func()
}

func (c *observingConn) Close() error {
	c.onClose()
	return nil
}

func index(t *testing.T, results []Result) map[string]Result {
	t.Helper()
	out := make(map[string]Result, len(results))
	for _, r := range results {
		address := r.IP.String()
		if r.Zone != "" {
			address += "%" + r.Zone
		}
		key := r.Host + "|" + address + "|" + strconv.Itoa(int(r.Port))
		if _, dup := out[key]; dup {
			t.Errorf("duplicate result for %s", key)
		}
		out[key] = r
	}
	return out
}

func TestNewDefaults(t *testing.T) {
	scanner := mustScanner(t)
	if scanner.concurrency != defaultConcurrency {
		t.Errorf("concurrency = %d, want %d", scanner.concurrency, defaultConcurrency)
	}
	if scanner.connectTimeout != defaultConnectTimeout {
		t.Errorf("connectTimeout = %s, want %s", scanner.connectTimeout, defaultConnectTimeout)
	}
	if scanner.dialer == nil || scanner.resolver == nil {
		t.Error("New left the dialer or the resolver unset")
	}
	if cap(scanner.sem) != defaultConcurrency {
		t.Errorf("connection budget = %d, want %d", cap(scanner.sem), defaultConcurrency)
	}
	if want := min(maxResolvers, defaultConcurrency); cap(scanner.resolverSem) != want {
		t.Errorf("resolver budget = %d, want %d", cap(scanner.resolverSem), want)
	}
	var (
		_ Dialer   = &net.Dialer{}
		_ Resolver = &net.Resolver{}
	)
}

func TestNewRejectsInvalidOptions(t *testing.T) {
	tests := []struct {
		name string
		opt  Option
	}{
		{name: "zero concurrency", opt: WithConcurrency(0)},
		{name: "negative concurrency", opt: WithConcurrency(-1)},
		{name: "zero timeout", opt: WithConnectTimeout(0)},
		{name: "negative timeout", opt: WithConnectTimeout(-time.Second)},
		{name: "nil dialer", opt: WithDialer(nil)},
		{name: "nil resolver", opt: WithResolver(nil)},
		{name: "nil option", opt: nil},
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

func TestLimitedResolverNeverLooksUpAfterCancellation(t *testing.T) {
	resolver := &fakeResolver{}
	limited := limitedResolver{resolver: resolver, sem: make(chan struct{}, 1)}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	for range 256 {
		if _, err := limited.LookupIPAddr(ctx, "canceled.example.com"); !errors.Is(err, context.Canceled) {
			t.Fatalf("LookupIPAddr error = %v, want %v", err, context.Canceled)
		}
	}
	if got := len(resolver.lookups()); got != 0 {
		t.Errorf("resolver was called %d times after cancellation", got)
	}
	if got := len(limited.sem); got != 0 {
		t.Errorf("resolver budget retained %d tokens after cancellation", got)
	}
}

func TestScanRejectsBadInput(t *testing.T) {
	scanner := mustScanner(t)
	ports := mustPorts(t, "80")

	t.Run("no targets", func(t *testing.T) {
		ch, err := scanner.Scan(t.Context(), nil, ports)
		if !errors.Is(err, ErrNoTargets) {
			t.Errorf("error = %v, want %v", err, ErrNoTargets)
		}
		if ch != nil {
			t.Error("channel is not nil")
		}
	})

	t.Run("empty target list", func(t *testing.T) {
		if _, err := scanner.Scan(t.Context(), []string{}, ports); !errors.Is(err, ErrNoTargets) {
			t.Errorf("error = %v, want %v", err, ErrNoTargets)
		}
	})

	t.Run("no ports", func(t *testing.T) {
		ch, err := scanner.Scan(t.Context(), []string{"1.2.3.4"}, PortSet{})
		if !errors.Is(err, ErrNoPorts) {
			t.Errorf("error = %v, want %v", err, ErrNoPorts)
		}
		if ch != nil {
			t.Error("channel is not nil")
		}
	})

	t.Run("malformed targets", func(t *testing.T) {
		ch, err := scanner.Scan(t.Context(), []string{"1.2.3.4", "", "host:80"}, ports)
		if err == nil {
			t.Fatal("Scan succeeded, want an error")
		}
		if ch != nil {
			t.Error("channel is not nil")
		}
		var target *TargetError
		if !errors.As(err, &target) {
			t.Fatalf("error = %v, want it to contain a *TargetError", err)
		}
	})

	t.Run("nil context", func(t *testing.T) {
		//lint:ignore SA1012 passing nil is exactly what is under test.
		if _, err := scanner.Scan(nil, []string{"1.2.3.4"}, ports); err == nil { //nolint:staticcheck
			t.Error("Scan with a nil context succeeded, want an error")
		}
	})
}

func TestScanRejectsUninitializedScanner(t *testing.T) {
	ports := mustPorts(t, "80")
	for _, tt := range []struct {
		name    string
		scanner *Scanner
	}{
		{name: "zero value", scanner: &Scanner{}},
		{name: "nil receiver", scanner: nil},
	} {
		t.Run(tt.name, func(t *testing.T) {
			ch, err := tt.scanner.Scan(t.Context(), []string{"192.0.2.1"}, ports)
			if !errors.Is(err, errUninitializedScanner) {
				t.Errorf("error = %v, want %v", err, errUninitializedScanner)
			}
			if ch != nil {
				t.Error("channel is not nil")
			}
		})
	}
}

func TestScanPreCanceledContextTakesPrecedenceOverInputErrors(t *testing.T) {
	resolver, dialer := &fakeResolver{}, &fakeDialer{}
	scanner := mustScanner(t, WithResolver(resolver), WithDialer(dialer))
	ports := mustPorts(t, "80")
	ctx, cancel := context.WithCancelCause(t.Context())
	cancel(errors.New("stop requested"))

	for _, tt := range []struct {
		name  string
		hosts []string
		ports PortSet
	}{
		{name: "valid input", hosts: []string{"valid.example.com"}, ports: ports},
		{name: "no targets", ports: ports},
		{name: "no ports", hosts: []string{"192.0.2.1"}},
		{name: "malformed target", hosts: []string{"host:80"}, ports: ports},
	} {
		t.Run(tt.name, func(t *testing.T) {
			ch, err := scanner.Scan(ctx, tt.hosts, tt.ports)
			if ch != nil || !errors.Is(err, context.Canceled) {
				t.Errorf("Scan = (%v, %v), want (nil, %v)", ch, err, context.Canceled)
			}
			results, err := scanner.ScanAll(ctx, tt.hosts, tt.ports)
			if results != nil || !errors.Is(err, context.Canceled) {
				t.Errorf("ScanAll = (%v, %v), want (nil, %v)", results, err, context.Canceled)
			}
		})
	}
	if ch, err := (&Scanner{}).Scan(ctx, nil, PortSet{}); ch != nil || !errors.Is(err, errUninitializedScanner) {
		t.Errorf("uninitialized Scan = (%v, %v), want (nil, %v)", ch, err, errUninitializedScanner)
	}
	if len(resolver.lookups()) != 0 || len(dialer.attempts()) != 0 {
		t.Error("pre-canceled scan started network work")
	}
}

func TestScanUnresolvedOncePerPort(t *testing.T) {
	resolverErr := &net.DNSError{Err: "no such host", Name: "nx.invalid", IsNotFound: true}
	resolver := &fakeResolver{err: resolverErr}
	dialer := &fakeDialer{}
	scanner := mustScanner(t, WithResolver(resolver), WithDialer(dialer))

	ch, err := scanner.Scan(t.Context(), []string{"nx.invalid"}, mustPorts(t, "80,443"))
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	results := drain(t, ch)

	if len(results) != 2 {
		t.Fatalf("got %d results, want exactly 2", len(results))
	}
	byKey := index(t, results)
	for i, port := range []string{"80", "443"} {
		r, ok := byKey["nx.invalid|<nil>|"+port]
		if !ok {
			t.Fatalf("no unresolved result for port %s", port)
		}
		if r.State != StateUnresolved {
			t.Errorf("port %s: State = %v, want %v", port, r.State, StateUnresolved)
		}
		if r.IP != nil {
			t.Errorf("port %s: IP = %v, want nil", port, r.IP)
		}
		var target *TargetError
		if !errors.As(r.Err, &target) || target.Target != "nx.invalid" {
			t.Errorf("port %s: Err = %v, want a *TargetError naming the target", port, r.Err)
		}
		var dnsErr *net.DNSError
		if !errors.As(r.Err, &dnsErr) || dnsErr != resolverErr {
			t.Errorf("port %s: Err = %v, want it to wrap the original resolver error", port, r.Err)
		}
		if i == 0 && target != nil {
			// The second result must own its wrapper, not share this mutation.
			target.Target = "modified"
			target.Err = nil
		}
	}
	if n := len(dialer.attempts()); n != 0 {
		t.Errorf("%d connections were attempted for a name that does not resolve", n)
	}
}

func TestScanMultipleAddressesPerName(t *testing.T) {
	resolver := newFakeResolver(map[string][]string{
		"multi.example.com": {"192.0.2.1", "192.0.2.2", "2001:db8::1"},
	})
	dialer := &fakeDialer{}
	scanner := mustScanner(t, WithResolver(resolver), WithDialer(dialer))

	results, err := scanner.ScanAll(t.Context(), []string{"multi.example.com"}, mustPorts(t, "80,443"))
	if err != nil {
		t.Fatalf("ScanAll: %v", err)
	}
	if len(results) != 6 {
		t.Fatalf("got %d results, want 6 (3 addresses x 2 ports)", len(results))
	}
	byKey := index(t, results)
	for _, ip := range []string{"192.0.2.1", "192.0.2.2", "2001:db8::1"} {
		for _, port := range []string{"80", "443"} {
			key := "multi.example.com|" + ip + "|" + port
			r, ok := byKey[key]
			if !ok {
				t.Fatalf("no result for %s", key)
			}
			if r.Host != "multi.example.com" {
				t.Errorf("Host = %q, want the target string", r.Host)
			}
			if r.State != StateOpen {
				t.Errorf("%s: State = %v, want %v", key, r.State, StateOpen)
			}
		}
	}
}

func TestScanFirstAddrOnly(t *testing.T) {
	resolver := newFakeResolver(map[string][]string{
		"multi.example.com": {"192.0.2.1", "192.0.2.2", "2001:db8::1"},
	})
	scanner := mustScanner(t, WithResolver(resolver), WithDialer(&fakeDialer{}), WithFirstAddrOnly())

	results, err := scanner.ScanAll(t.Context(), []string{"multi.example.com"}, mustPorts(t, "80"))
	if err != nil {
		t.Fatalf("ScanAll: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("got %d results, want 1", len(results))
	}
	if got := results[0].IP.String(); got != "192.0.2.1" {
		t.Errorf("IP = %s, want the first address 192.0.2.1", got)
	}
}

func TestScanCIDR(t *testing.T) {
	dialer := &fakeDialer{}
	scanner := mustScanner(t, WithDialer(dialer))

	results, err := scanner.ScanAll(t.Context(), []string{"10.0.0.0/30"}, mustPorts(t, "80,443"))
	if err != nil {
		t.Fatalf("ScanAll: %v", err)
	}
	if len(results) != 8 {
		t.Fatalf("got %d results, want 8 (4 addresses x 2 ports)", len(results))
	}
	byKey := index(t, results)
	for _, ip := range []string{"10.0.0.0", "10.0.0.1", "10.0.0.2", "10.0.0.3"} {
		for _, port := range []string{"80", "443"} {
			key := "10.0.0.0/30|" + ip + "|" + port
			if _, ok := byKey[key]; !ok {
				t.Fatalf("no result for %s", key)
			}
		}
	}
	firstOnly := mustScanner(t, WithDialer(&fakeDialer{}), WithFirstAddrOnly())
	results, err = firstOnly.ScanAll(t.Context(), []string{"10.0.0.0/30"}, mustPorts(t, "80"))
	if err != nil {
		t.Fatalf("ScanAll: %v", err)
	}
	if len(results) != 4 {
		t.Errorf("with WithFirstAddrOnly a prefix gave %d results, want 4", len(results))
	}
}

func TestScanDeduplicatesTargets(t *testing.T) {
	dialer := &fakeDialer{}
	scanner := mustScanner(t, WithDialer(dialer))

	results, err := scanner.ScanAll(t.Context(),
		[]string{"192.0.2.1", "192.0.2.1", "192.0.2.1"}, mustPorts(t, "80,443"))
	if err != nil {
		t.Fatalf("ScanAll: %v", err)
	}
	if len(results) != 2 {
		t.Fatalf("got %d results, want 2: repeated targets collapse", len(results))
	}
	index(t, results)
}

func TestScanKeepsDistinctNamesOnOneAddress(t *testing.T) {
	resolver := newFakeResolver(map[string][]string{
		"a.example.com": {"192.0.2.1"},
		"b.example.com": {"192.0.2.1"},
	})
	scanner := mustScanner(t, WithResolver(resolver), WithDialer(&fakeDialer{}))

	results, err := scanner.ScanAll(t.Context(),
		[]string{"a.example.com", "b.example.com"}, mustPorts(t, "80"))
	if err != nil {
		t.Fatalf("ScanAll: %v", err)
	}
	if len(results) != 2 {
		t.Fatalf("got %d results, want 2", len(results))
	}
	hosts := []string{results[0].Host, results[1].Host}
	slices.Sort(hosts)
	if !slices.Equal(hosts, []string{"a.example.com", "b.example.com"}) {
		t.Errorf("hosts = %v, want both names", hosts)
	}
}

func TestScanDeduplicatesAddressesWithinATarget(t *testing.T) {
	resolver := newFakeResolver(map[string][]string{
		"dup.example.com": {"192.0.2.1", "192.0.2.1", "::ffff:192.0.2.1"},
	})
	scanner := mustScanner(t, WithResolver(resolver), WithDialer(&fakeDialer{}))

	results, err := scanner.ScanAll(t.Context(), []string{"dup.example.com"}, mustPorts(t, "80"))
	if err != nil {
		t.Fatalf("ScanAll: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("got %d results, want 1", len(results))
	}
}

func TestScanClosesEveryConnection(t *testing.T) {
	dialer := &fakeDialer{}
	scanner := mustScanner(t, WithDialer(dialer))

	if _, err := scanner.ScanAll(t.Context(), []string{"192.0.2.1"}, mustPorts(t, "1-100")); err != nil {
		t.Fatalf("ScanAll: %v", err)
	}
	if n := len(dialer.conns); n != 100 {
		t.Fatalf("%d connections were opened, want 100", n)
	}
	dialer.assertAllConnsClosed(t)
}

func TestScanDialsLiteralsOnly(t *testing.T) {
	resolver := newFakeResolver(map[string][]string{
		"multi.example.com": {"192.0.2.1", "2001:db8::1"},
	})
	dialer := &fakeDialer{}
	scanner := mustScanner(t, WithResolver(resolver), WithDialer(dialer))

	if _, err := scanner.ScanAll(t.Context(), []string{"multi.example.com"}, mustPorts(t, "80")); err != nil {
		t.Fatalf("ScanAll: %v", err)
	}
	attempts := dialer.attempts()
	if len(attempts) != 2 {
		t.Fatalf("got %d attempts, want 2", len(attempts))
	}
	for _, address := range attempts {
		host, port, err := net.SplitHostPort(address)
		if err != nil {
			t.Fatalf("SplitHostPort(%q): %v", address, err)
		}
		if net.ParseIP(host) == nil {
			t.Errorf("dialled %q, which is not an IP literal", address)
		}
		if port != "80" {
			t.Errorf("dialled port %q, want 80", port)
		}
	}
}

func TestScanPreservesIPv6Zone(t *testing.T) {
	dialer := &fakeDialer{}
	scanner := mustScanner(t, WithDialer(dialer))

	results, err := scanner.ScanAll(t.Context(), []string{"fe80::1%en0"}, mustPorts(t, "80"))
	if err != nil {
		t.Fatalf("ScanAll: %v", err)
	}
	if want := []string{"[fe80::1%en0]:80"}; !slices.Equal(dialer.attempts(), want) {
		t.Errorf("dialled %v, want %v", dialer.attempts(), want)
	}
	if len(results) != 1 {
		t.Fatalf("got %d results, want 1", len(results))
	}
	if results[0].Host != "fe80::1%en0" || results[0].Zone != "en0" ||
		!results[0].IP.Equal(net.ParseIP("fe80::1")) {
		t.Errorf("result endpoint = (%q, %v, %q), want scoped fe80::1%%en0",
			results[0].Host, results[0].IP, results[0].Zone)
	}
}

func TestResultErrorInvariant(t *testing.T) {
	resolver := newFakeResolver(map[string][]string{"mixed.example.com": {"192.0.2.1"}})
	dialer := &fakeDialer{
		dial: func(_ context.Context, address string) (net.Conn, error) {
			switch {
			case strings.HasSuffix(address, ":80"):
				return &fakeConn{}, nil
			case strings.HasSuffix(address, ":81"):
				return nil, opErr(errors.New("boom"))
			default:
				return nil, opErr(os.ErrDeadlineExceeded)
			}
		},
	}
	scanner := mustScanner(t, WithResolver(resolver), WithDialer(dialer))

	results, err := scanner.ScanAll(t.Context(),
		[]string{"mixed.example.com", "nx.invalid"}, mustPorts(t, "80-82"))
	if err != nil {
		t.Fatalf("ScanAll: %v", err)
	}
	if len(results) != 6 {
		t.Fatalf("got %d results, want 6", len(results))
	}
	for _, r := range results {
		if (r.State == StateOpen) != (r.Err == nil) {
			t.Errorf("%v: State == StateOpen is %t but Err == nil is %t",
				r, r.State == StateOpen, r.Err == nil)
		}
	}
}

func TestScanAndScanAllHaveEquivalentResults(t *testing.T) {
	resolver := newFakeResolver(map[string][]string{
		"multi.example.com": {"192.0.2.1", "2001:db8::1"},
	})
	dialer := &fakeDialer{dial: func(_ context.Context, address string) (net.Conn, error) {
		if strings.HasSuffix(address, ":443") {
			return nil, opErr(os.ErrDeadlineExceeded)
		}
		return &fakeConn{}, nil
	}}
	scanner := mustScanner(t, WithDialer(dialer), WithResolver(resolver))
	hosts := []string{"multi.example.com", "nx.invalid", "192.0.2.4/31", "multi.example.com"}
	ports := mustPorts(t, "80,443")
	ch, err := scanner.Scan(t.Context(), hosts, ports)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	streamed := index(t, drain(t, ch))
	results, err := scanner.ScanAll(t.Context(), hosts, ports)
	if err != nil {
		t.Fatalf("ScanAll: %v", err)
	}
	collected := index(t, results)
	if len(streamed) != len(collected) {
		t.Errorf("Scan returned %d results, ScanAll returned %d", len(streamed), len(collected))
	}
	for key, want := range streamed {
		got, ok := collected[key]
		// Durations are measurements of different attempts, not part of the comparison.
		if !ok || got.State != want.State || fmt.Sprint(got.Err) != fmt.Sprint(want.Err) {
			t.Errorf("ScanAll[%s] = %v (present: %t), Scan = %v", key, got, ok, want)
		}
	}
}

func TestScanAllReturnsContextError(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	dialer := &fakeDialer{dial: func(ctx context.Context, _ string) (net.Conn, error) {
		cancel()
		<-ctx.Done()
		return nil, opErr(context.Canceled)
	}}
	scanner := mustScanner(t, WithDialer(dialer), WithConcurrency(1))

	results, err := scanner.ScanAll(ctx, []string{"192.0.2.1"}, mustPorts(t, "1-100"))
	if !errors.Is(err, context.Canceled) {
		t.Errorf("error = %v, want %v", err, context.Canceled)
	}
	if len(results) > 100 {
		t.Errorf("got %d results, want at most 100", len(results))
	}
}

func TestProbeClassifiesAndCancelsBeforeCleanup(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancelScan := context.WithCancel(t.Context())
		defer cancelScan()
		closing := make(chan error)
		releaseClose := make(chan struct{})
		dialErr := opErr(errors.New("dial failed"))
		dialer := &fakeDialer{dial: func(dialCtx context.Context, _ string) (net.Conn, error) {
			return &observingConn{onClose: func() {
				closing <- dialCtx.Err()
				<-releaseClose
			}}, dialErr
		}}
		scanner := mustScanner(t, WithDialer(dialer), WithConcurrency(1))

		// A slot is deliberately ready so best-effort delivery after cancel is
		// deterministic. The test controls when the scan is canceled during Close.
		results := make(chan Result, 1)
		go func() {
			defer close(results)
			j := job{host: "192.0.2.1", addr: net.IPAddr{IP: net.ParseIP("192.0.2.1")}, port: 80}
			scanner.probe(ctx, j, results)
		}()
		if closeContextErr := <-closing; !errors.Is(closeContextErr, context.Canceled) {
			t.Errorf("attempt context at Close = %v, want %v", closeContextErr, context.Canceled)
		}
		cancelScan()
		close(releaseClose)

		got := drain(t, results)
		if len(got) != 1 || got[0].State != StateError || !errors.Is(got[0].Err, dialErr) {
			t.Errorf("results = %v, want one with StateError and the dial error", got)
		}
	})
}

func TestProbeRejectsNilSuccessfulConnection(t *testing.T) {
	for _, test := range []struct {
		name string
		conn net.Conn
	}{
		{name: "nil interface"},
		{name: "typed nil", conn: (*fakeConn)(nil)},
	} {
		t.Run(test.name, func(t *testing.T) {
			dialer := &fakeDialer{dial: func(context.Context, string) (net.Conn, error) {
				return test.conn, nil
			}}
			scanner := mustScanner(t, WithDialer(dialer))

			results, err := scanner.ScanAll(t.Context(), []string{"192.0.2.1"}, mustPorts(t, "80"))
			if err != nil {
				t.Fatalf("ScanAll: %v", err)
			}
			if len(results) != 1 {
				t.Fatalf("got %d results, want 1", len(results))
			}
			if results[0].State != StateError || !errors.Is(results[0].Err, errNilConnection) {
				t.Errorf("result = %v, want StateError wrapping %v", results[0], errNilConnection)
			}
		})
	}
}

func TestProbePublishesOwnedIP(t *testing.T) {
	dialer := &fakeDialer{}
	scanner := mustScanner(t, WithDialer(dialer), WithConcurrency(1))
	results := make(chan Result, 1)
	sharedIP := net.ParseIP("192.0.2.1")

	first := job{host: "192.0.2.1", addr: net.IPAddr{IP: sharedIP}, port: 80}
	if !scanner.probe(t.Context(), first, results) {
		t.Fatal("first probe stopped the worker")
	}
	firstResult := <-results
	for i := range firstResult.IP {
		firstResult.IP[i] = 0
	}

	second := job{host: "192.0.2.1", addr: net.IPAddr{IP: sharedIP}, port: 81}
	if !scanner.probe(t.Context(), second, results) {
		t.Fatal("second probe stopped the worker")
	}
	secondResult := <-results
	if got := secondResult.IP.String(); got != "192.0.2.1" {
		t.Errorf("second result IP changed after mutating the first: got %q", got)
	}
	if want := []string{"192.0.2.1:80", "192.0.2.1:81"}; !slices.Equal(dialer.attempts(), want) {
		t.Errorf("dialled %v, want %v", dialer.attempts(), want)
	}
}

func TestScanPublishesIndependentlyOwnedIPs(t *testing.T) {
	const host = "owned.example.com"
	resolver := newFakeResolver(map[string][]string{host: {"192.0.2.1"}})
	dialer := &fakeDialer{}
	scanner := mustScanner(t,
		WithResolver(resolver),
		WithDialer(dialer),
		WithConcurrency(8),
	)
	ports := mustPorts(t, "1-256")

	results, err := scanner.Scan(t.Context(), []string{host}, ports)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	count := 0
	for result := range results {
		if got := result.IP.String(); got != "192.0.2.1" {
			t.Fatalf("result %d IP = %q after earlier caller mutations, want 192.0.2.1", count, got)
		}
		for i := range result.IP {
			result.IP[i] = 0
		}
		count++
	}
	if count != ports.Len() {
		t.Fatalf("got %d results, want %d", count, ports.Len())
	}
	for _, address := range dialer.attempts() {
		dialedHost, _, err := net.SplitHostPort(address)
		if err != nil {
			t.Fatalf("SplitHostPort(%q): %v", address, err)
		}
		if dialedHost != "192.0.2.1" {
			t.Fatalf("dialed %q after caller mutation, want 192.0.2.1", dialedHost)
		}
	}
}

func TestProbeNeverDialsAfterCancellation(t *testing.T) {
	dialer := &fakeDialer{}
	scanner := mustScanner(t, WithDialer(dialer), WithConcurrency(1))
	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	results := make(chan Result, 256)
	j := job{host: "192.0.2.1", addr: net.IPAddr{IP: net.ParseIP("192.0.2.1")}, port: 80}
	for range cap(results) {
		scanner.probe(ctx, j, results)
	}
	if got := len(dialer.attempts()); got != 0 {
		t.Errorf("dialer was invoked %d times after cancellation", got)
	}
	if got := len(scanner.sem); got != 0 {
		t.Errorf("semaphore retained %d tokens after cancellation", got)
	}
}

func TestScannerReuse(t *testing.T) {
	dialer := &fakeDialer{}
	scanner := mustScanner(t, WithDialer(dialer))
	ports := mustPorts(t, "80,443")

	for i := range 3 {
		results, err := scanner.ScanAll(t.Context(), []string{"192.0.2.1"}, ports)
		if err != nil {
			t.Fatalf("scan %d: %v", i, err)
		}
		if len(results) != 2 {
			t.Fatalf("scan %d: got %d results, want 2", i, len(results))
		}
	}
	if n := len(dialer.attempts()); n != 6 {
		t.Errorf("%d attempts in total, want 6", n)
	}
}
