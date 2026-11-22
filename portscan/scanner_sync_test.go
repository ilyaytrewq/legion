package portscan

import (
	"context"
	"net"
	"sync"
	"testing"
	"testing/synctest"
	"time"
)

type lookupProbe struct {
	mu       sync.Mutex
	inFlight int
	peak     int
}

func (p *lookupProbe) start() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.inFlight++
	p.peak = max(p.peak, p.inFlight)
}

func (p *lookupProbe) stop() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.inFlight--
}

func (p *lookupProbe) peakInFlight() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.peak
}

func TestCancelStopsNewAttempts(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()

		dialer := &fakeDialer{dial: func(ctx context.Context, _ string) (net.Conn, error) {
			<-ctx.Done()
			return nil, opErr(context.Canceled)
		}}
		scanner := mustScanner(t, WithDialer(dialer), WithConcurrency(4))

		ch, err := scanner.Scan(ctx, []string{"192.0.2.1"}, mustPorts(t, "1-8"))
		if err != nil {
			t.Fatalf("Scan: %v", err)
		}

		synctest.Wait()
		if got := len(dialer.attempts()); got != 4 {
			t.Fatalf("%d attempts in flight, want 4 (the concurrency limit)", got)
		}

		cancel()
		results := drain(t, ch)

		if got := len(dialer.attempts()); got != 4 {
			t.Errorf("%d attempts in total, want 4: cancellation must stop new attempts", got)
		}
		if len(results) > 4 {
			t.Fatalf("got %d results, want at most 4", len(results))
		}
		for _, r := range results {
			if r.State != StateCanceled {
				t.Errorf("%v: State = %v, want %v", r, r.State, StateCanceled)
			}
			if r.Err == nil {
				t.Errorf("%v: Err is nil for a state other than open", r)
			}
		}
	})
}

func TestSlowConsumerAppliesBackpressure(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()

		const concurrency = 4
		dialer := &fakeDialer{}
		scanner := mustScanner(t, WithDialer(dialer), WithConcurrency(concurrency))

		ch, err := scanner.Scan(ctx, []string{"192.0.2.1"}, mustPorts(t, "1-100"))
		if err != nil {
			t.Fatalf("Scan: %v", err)
		}

		synctest.Wait()
		const settled = concurrency
		if got := len(dialer.attempts()); got != settled {
			t.Fatalf("%d attempts once the scan settled, want %d", got, settled)
		}

		<-ch
		synctest.Wait()
		if got := len(dialer.attempts()); got != settled+1 {
			t.Errorf("%d attempts after taking one result, want %d: reading must "+
				"release exactly one attempt", got, settled+1)
		}

		cancel()
		drain(t, ch)
	})
}

func TestConcurrencyLimitIsPerScanner(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		const (
			limit = 10
			scans = 4
		)
		dialer := &fakeDialer{dial: func(context.Context, string) (net.Conn, error) {
			time.Sleep(10 * time.Millisecond)
			return nil, opErr(context.DeadlineExceeded)
		}}
		scanner := mustScanner(t, WithDialer(dialer), WithConcurrency(limit))
		ports := mustPorts(t, "1-25")

		var wg sync.WaitGroup
		for range scans {
			wg.Add(1)
			go func() {
				defer wg.Done()
				results, err := scanner.ScanAll(t.Context(), []string{"192.0.2.1"}, ports)
				if err != nil {
					t.Errorf("ScanAll: %v", err)
				}
				if len(results) != ports.Len() {
					t.Errorf("got %d results, want %d", len(results), ports.Len())
				}
			}()
		}
		wg.Wait()

		if peak := dialer.peakInFlight(); peak != limit {
			t.Errorf("peak concurrency = %d, want exactly %d across %d scans "+
				"sharing one Scanner", peak, limit, scans)
		}
		if got := len(dialer.attempts()); got != scans*ports.Len() {
			t.Errorf("%d attempts in total, want %d", got, scans*ports.Len())
		}
	})
}

func TestResolverLimitIsPerScanner(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		const (
			limit          = 4
			scans          = 4
			targetsPerScan = 8
		)
		probe := &lookupProbe{}
		resolver := &fakeResolver{hook: func(context.Context, string) error {
			probe.start()
			defer probe.stop()
			time.Sleep(10 * time.Millisecond)
			return nil
		}}
		scanner := mustScanner(t,
			WithResolver(resolver),
			WithDialer(&fakeDialer{}),
			WithConcurrency(limit),
		)
		hosts := make([]string, targetsPerScan)
		for i := range hosts {
			hosts[i] = "resolver-" + string(rune('a'+i)) + ".example.com"
		}
		ports := mustPorts(t, "1")

		var wg sync.WaitGroup
		for range scans {
			wg.Add(1)
			go func() {
				defer wg.Done()
				if _, err := scanner.ScanAll(t.Context(), hosts, ports); err != nil {
					t.Errorf("ScanAll: %v", err)
				}
			}()
		}
		wg.Wait()

		if peak := probe.peakInFlight(); peak != limit {
			t.Errorf("peak lookup concurrency = %d, want exactly %d across %d scans",
				peak, limit, scans)
		}
		if got := len(resolver.lookups()); got != scans*targetsPerScan {
			t.Errorf("%d lookups in total, want %d", got, scans*targetsPerScan)
		}
		if got := len(scanner.resolverSem); got != 0 {
			t.Errorf("resolver budget retained %d tokens after all scans completed", got)
		}
	})
}

func TestResolverWaitStopsAfterCancellation(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		const limit = 2
		probe := &lookupProbe{}
		resolver := &fakeResolver{hook: func(ctx context.Context, _ string) error {
			probe.start()
			defer probe.stop()
			<-ctx.Done()
			return ctx.Err()
		}}
		scanner := mustScanner(t,
			WithResolver(resolver),
			WithDialer(&fakeDialer{}),
			WithConcurrency(limit),
		)
		ports := mustPorts(t, "1")

		firstCtx, cancelFirst := context.WithCancel(t.Context())
		defer cancelFirst()
		first, err := scanner.Scan(firstCtx,
			[]string{"first-a.example.com", "first-b.example.com"}, ports)
		if err != nil {
			t.Fatalf("first Scan: %v", err)
		}
		synctest.Wait()
		if got := len(resolver.lookups()); got != limit {
			t.Fatalf("%d lookups in first scan, want %d", got, limit)
		}

		secondCtx, cancelSecond := context.WithCancel(t.Context())
		second, err := scanner.Scan(secondCtx,
			[]string{"second-a.example.com", "second-b.example.com"}, ports)
		if err != nil {
			t.Fatalf("second Scan: %v", err)
		}
		synctest.Wait()
		if got := len(resolver.lookups()); got != limit {
			t.Fatalf("%d lookups while second scan waits, want %d", got, limit)
		}

		cancelSecond()
		synctest.Wait()
		if got := len(resolver.lookups()); got != limit {
			t.Errorf("%d lookups after second scan cancellation, want %d", got, limit)
		}

		cancelFirst()
		drain(t, second)
		drain(t, first)
		if got := len(resolver.lookups()); got != limit {
			t.Errorf("%d lookups in total, want %d", got, limit)
		}
		if got := len(scanner.resolverSem); got != 0 {
			t.Errorf("resolver budget retained %d tokens after cancellation", got)
		}
	})
}

func TestCloseWaitsForResolverIgnoringCancellation(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		release := make(chan struct{})
		resolver := newFakeResolver(map[string][]string{
			"fast.example.com": {"192.0.2.1"},
		})
		resolver.hook = func(_ context.Context, host string) error {
			if host == "stuck.example.com" {
				<-release
			}
			return nil
		}
		scanner := mustScanner(t,
			WithResolver(resolver),
			WithDialer(&fakeDialer{}),
			WithConcurrency(2),
		)

		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		ch, err := scanner.Scan(ctx,
			[]string{"fast.example.com", "stuck.example.com"}, mustPorts(t, "1-100"))
		if err != nil {
			t.Fatalf("Scan: %v", err)
		}

		synctest.Wait()
		if got := len(scanner.resolverSem); got != 1 {
			t.Fatalf("resolver tokens held = %d, want 1", got)
		}

		cancel()
		closed := make(chan struct{})
		go func() {
			for range ch {
			}
			close(closed)
		}()

		synctest.Wait()
		select {
		case <-closed:
			t.Fatal("results closed while a resolver was still inside LookupIPAddr")
		default:
		}
		if got := len(scanner.resolverSem); got != 1 {
			t.Fatalf("resolver tokens held = %d after cancellation, want 1", got)
		}

		close(release)
		synctest.Wait()
		<-closed
		if got := len(scanner.resolverSem); got != 0 {
			t.Errorf("resolver budget retained %d tokens after close", got)
		}
	})
}

func TestConnectTimeoutIsPerAttempt(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		const timeout = 500 * time.Millisecond
		dialer := &fakeDialer{dial: blockUntilDeadline}
		scanner := mustScanner(t,
			WithDialer(dialer),
			WithConnectTimeout(timeout),
			WithConcurrency(2),
		)

		start := time.Now()
		results, err := scanner.ScanAll(t.Context(), []string{"192.0.2.1"}, mustPorts(t, "80,443"))
		if err != nil {
			t.Fatalf("ScanAll: %v", err)
		}

		if len(results) != 2 {
			t.Fatalf("got %d results, want 2", len(results))
		}
		for _, r := range results {
			if r.State != StateTimeout {
				t.Errorf("%v: State = %v, want %v", r, r.State, StateTimeout)
			}
			if r.Duration != timeout {
				t.Errorf("%v: Duration = %v, want exactly %v", r, r.Duration, timeout)
			}
		}
		if elapsed := time.Since(start); elapsed != timeout {
			t.Errorf("the scan took %v, want exactly %v", elapsed, timeout)
		}
	})
}

func TestConnectionsClosedWhenResultsAreDropped(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()

		const concurrency = 2
		dialer := &fakeDialer{}
		scanner := mustScanner(t, WithDialer(dialer), WithConcurrency(concurrency))

		ch, err := scanner.Scan(ctx, []string{"192.0.2.1"}, mustPorts(t, "1-50"))
		if err != nil {
			t.Fatalf("Scan: %v", err)
		}

		synctest.Wait()
		if got := len(dialer.conns); got != concurrency {
			t.Fatalf("%d connections were opened, want %d", got, 2*concurrency)
		}

		cancel()
		drain(t, ch)
		dialer.assertAllConnsClosed(t)
	})
}

func TestCancelDuringResolution(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()

		resolver := &fakeResolver{hook: func(ctx context.Context, _ string) error {
			<-ctx.Done()
			return &net.DNSError{Err: "operation was canceled", Name: "slow.example.com"}
		}}
		dialer := &fakeDialer{}
		scanner := mustScanner(t, WithResolver(resolver), WithDialer(dialer))

		ch, err := scanner.Scan(ctx, []string{"slow.example.com"}, mustPorts(t, "1-100"))
		if err != nil {
			t.Fatalf("Scan: %v", err)
		}

		synctest.Wait()
		if got := len(dialer.attempts()); got != 0 {
			t.Fatalf("%d attempts were made before the name resolved", got)
		}

		cancel()
		results := drain(t, ch)

		if len(results) != 0 {
			t.Errorf("got %d results: resolution only finished after cancellation", len(results))
		}
		if got := len(dialer.attempts()); got != 0 {
			t.Errorf("%d attempts were made for a name that never resolved", got)
		}
	})
}

func TestWorkerMayEmitPreviouslyQueuedResolutionFailureAfterCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	jobs := make(chan job, 1)
	jobs <- job{
		host:   "nx.invalid",
		port:   443,
		preErr: &TargetError{Target: "nx.invalid", Err: errNoAddresses},
	}
	close(jobs)
	results := make(chan Result, 1)

	(&Scanner{}).work(ctx, jobs, results)
	select {
	case result := <-results:
		if result.State != StateUnresolved || result.Port != 443 {
			t.Errorf("result = %v, want unresolved port 443", result)
		}
	default:
		t.Fatal("previously queued resolution failure was not delivered")
	}
}

func TestScanLeavesNoGoroutinesBehind(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		resolver := newFakeResolver(map[string][]string{
			"multi.example.com": {"192.0.2.1", "192.0.2.2"},
		})
		scanner := mustScanner(t,
			WithResolver(resolver),
			WithDialer(&fakeDialer{}),
			WithConcurrency(8),
		)

		results, err := scanner.ScanAll(t.Context(),
			[]string{"multi.example.com", "10.0.0.0/29", "nx.invalid"}, mustPorts(t, "1-20"))
		if err != nil {
			t.Fatalf("ScanAll: %v", err)
		}
		if want := 10*20 + 20; len(results) != want {
			t.Errorf("got %d results, want %d", len(results), want)
		}
	})
}
