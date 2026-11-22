package portscan

import (
	"context"
	"net"
	"testing"
	"testing/synctest"
)

func TestSubmissionAndResultsUseDifferentCancellationPriorities(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	out := make(chan Result, 1)
	result := Result{Port: 443, State: StateOpen}
	if submit(ctx, out, result) || len(out) != 0 {
		t.Fatal("submitted work after cancellation even though a slot was ready")
	}
	if !sendResult(ctx, out, result) {
		t.Fatal("completed result was dropped even though a slot was ready")
	}
	if sendResult(ctx, out, result) {
		t.Fatal("published a completed result after cancellation with no available slot")
	}
}

func TestTargetFeederStopsWhileBlockedOnSubmission(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		out, done := feedTargets(ctx, []target{{raw: "first"}, {raw: "second"}})
		if cap(out) != 0 {
			t.Fatal("target feeder should not buffer targets")
		}
		if got := <-out; got.raw != "first" {
			t.Errorf("first target = %q, want first", got.raw)
		}
		synctest.Wait() // Feeder cannot send the second target until another receive.
		cancel()
		<-done
		if got, ok := <-out; ok {
			t.Errorf("unexpected target %q after feeder stopped", got.raw)
		}
	})
}

func TestProbeWorkerCount(t *testing.T) {
	for _, tt := range []struct {
		name      string
		hosts     []string
		ports     int
		firstOnly bool
		want      int
	}{
		{name: "single literal", hosts: []string{"192.0.2.1"}, ports: 1, want: 1},
		{name: "small mixed workload", hosts: []string{"192.0.2.1", "192.0.2.4/31"}, ports: 2, want: 6},
		{name: "first address only", hosts: []string{"multi.example.com"}, ports: 2, firstOnly: true, want: 2},
		{name: "unknown DNS cardinality", hosts: []string{"multi.example.com"}, ports: 1, want: 8},
		{name: "large prefix", hosts: []string{"2001:db8::/112"}, ports: 65535, want: 8},
	} {
		t.Run(tt.name, func(t *testing.T) {
			scanner := mustScanner(t, WithConcurrency(8))
			scanner.firstAddrOnly = tt.firstOnly
			targets, err := parseTargets(t.Context(), tt.hosts)
			if err != nil {
				t.Fatalf("parseTargets: %v", err)
			}
			if got := scanner.probeWorkerCount(targets, tt.ports); got != tt.want {
				t.Errorf("probe workers = %d, want %d", got, tt.want)
			}
		})
	}
}

func TestProbeParallelismAcrossExpandedAddresses(t *testing.T) {
	for _, host := range []string{"four.example.com", "192.0.2.4/30"} {
		t.Run(host, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				release := make(chan struct{})
				dialer := &fakeDialer{dial: func(context.Context, string) (net.Conn, error) {
					<-release
					return &fakeConn{}, nil
				}}
				resolver := newFakeResolver(map[string][]string{
					"four.example.com": {"192.0.2.1", "192.0.2.2", "192.0.2.3", "192.0.2.4"},
				})
				scanner := mustScanner(t, WithConcurrency(8), WithDialer(dialer), WithResolver(resolver))
				results, err := scanner.Scan(t.Context(), []string{host}, mustPorts(t, "80"))
				if err != nil {
					t.Fatalf("Scan: %v", err)
				}
				synctest.Wait()
				if got := dialer.peakInFlight(); got != 4 {
					t.Errorf("peak parallel probes = %d, want 4", got)
				}
				close(release)
				if got := len(drain(t, results)); got != 4 {
					t.Errorf("got %d results, want 4", got)
				}
			})
		})
	}
}
