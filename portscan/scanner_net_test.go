package portscan

import (
	"errors"
	"net"
	"os"
	"strconv"
	"testing"
	"time"
)

func listenLoopback(t *testing.T) (port int) {
	t.Helper()
	ln := listenTCPOrSkip(t, "127.0.0.1:0")
	serveLoopback(t, ln)
	return ln.Addr().(*net.TCPAddr).Port
}

func serveLoopback(t *testing.T, ln net.Listener) {
	t.Helper()
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			conn.Close()
		}
	}()
	t.Cleanup(func() {
		ln.Close()
		<-done
	})
}

func listenTCPOrSkip(t *testing.T, address string) net.Listener {
	t.Helper()
	ln, err := net.Listen("tcp", address)
	if err != nil {
		if errors.Is(err, os.ErrPermission) {
			t.Skipf("loopback bind is not permitted in this environment: %v", err)
		}
		t.Fatalf("Listen: %v", err)
	}
	return ln
}

func TestScanOpenPortOnLoopback(t *testing.T) {
	port := listenLoopback(t)
	scanner := mustScanner(t, WithConnectTimeout(2*time.Second))

	results, err := scanner.ScanAll(t.Context(),
		[]string{"127.0.0.1"}, mustPorts(t, strconv.Itoa(port)))
	if err != nil {
		t.Fatalf("ScanAll: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("got %d results, want 1", len(results))
	}

	r := results[0]
	if r.State != StateOpen {
		t.Fatalf("State = %v (%v), want %v", r.State, r.Err, StateOpen)
	}
	if r.Err != nil {
		t.Errorf("Err = %v, want nil for an open port", r.Err)
	}
	if !r.IP.Equal(net.IPv4(127, 0, 0, 1)) {
		t.Errorf("IP = %v, want 127.0.0.1", r.IP)
	}
	if int(r.Port) != port {
		t.Errorf("Port = %d, want %d", r.Port, port)
	}
	if r.Host != "127.0.0.1" {
		t.Errorf("Host = %q, want the target string", r.Host)
	}
}

func TestScanOpenPortOnIPv6Loopback(t *testing.T) {
	ln, err := net.Listen("tcp6", "[::1]:0")
	if err != nil {
		t.Skipf("IPv6 loopback is unavailable in this environment: %v", err)
	}
	serveLoopback(t, ln)
	port := ln.Addr().(*net.TCPAddr).Port
	scanner := mustScanner(t, WithConnectTimeout(2*time.Second))

	results, err := scanner.ScanAll(t.Context(), []string{"::1"}, mustPorts(t, strconv.Itoa(port)))
	if err != nil {
		t.Fatalf("ScanAll: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("got %d results, want 1", len(results))
	}
	if result := results[0]; result.State != StateOpen || !result.IP.Equal(net.ParseIP("::1")) || result.Zone != "" {
		t.Errorf("result = %v, want open unscoped IPv6 loopback", result)
	}
}

func TestScanClosedPortOnLoopback(t *testing.T) {
	scanner := mustScanner(t, WithConnectTimeout(2*time.Second))

	var last Result
	for attempt := range 3 {
		ln := listenTCPOrSkip(t, "127.0.0.1:0")
		port := ln.Addr().(*net.TCPAddr).Port
		if err := ln.Close(); err != nil {
			t.Fatalf("Close: %v", err)
		}

		results, err := scanner.ScanAll(t.Context(),
			[]string{"127.0.0.1"}, mustPorts(t, strconv.Itoa(port)))
		if err != nil {
			t.Fatalf("ScanAll: %v", err)
		}
		if len(results) != 1 {
			t.Fatalf("got %d results, want 1", len(results))
		}
		last = results[0]
		if last.State == StateClosed {
			if last.Err == nil {
				t.Error("Err is nil for a closed port")
			}
			if errors.Is(last.Err, ErrResourceExhausted) {
				t.Error("a refused connection was reported as resource exhaustion")
			}
			return
		}
		t.Logf("attempt %d: port %d came back as %v", attempt+1, port, last.State)
	}
	t.Fatalf("State = %v (%v), want %v", last.State, last.Err, StateClosed)
}

func TestScanRangeOnLoopback(t *testing.T) {
	port := listenLoopback(t)
	scanner := mustScanner(t, WithConcurrency(8), WithConnectTimeout(2*time.Second))

	from, to := max(1, port-4), min(maxPort, port+4)
	spec := strconv.Itoa(from) + "-" + strconv.Itoa(to)

	results, err := scanner.ScanAll(t.Context(), []string{"127.0.0.1"}, mustPorts(t, spec))
	if err != nil {
		t.Fatalf("ScanAll: %v", err)
	}
	if want := to - from + 1; len(results) != want {
		t.Fatalf("got %d results, want %d", len(results), want)
	}

	byKey := index(t, results)
	key := "127.0.0.1|127.0.0.1|" + strconv.Itoa(port)
	r, ok := byKey[key]
	if !ok {
		t.Fatalf("no result for the listening port %d", port)
	}
	if r.State != StateOpen {
		t.Errorf("the listening port came back as %v (%v), want %v", r.State, r.Err, StateOpen)
	}
	for _, r := range results {
		if (r.State == StateOpen) != (r.Err == nil) {
			t.Errorf("%v: Err must be nil exactly when the port is open", r)
		}
	}
}

func TestScanLocalhostWithRealResolver(t *testing.T) {
	port := listenLoopback(t)

	addrs, err := net.DefaultResolver.LookupIPAddr(t.Context(), "localhost")
	if err != nil {
		t.Skipf("localhost does not resolve here: %v", err)
	}
	want := len(dedupAddrs(addrs))

	scanner := mustScanner(t, WithConnectTimeout(2*time.Second))
	results, err := scanner.ScanAll(t.Context(),
		[]string{"localhost"}, mustPorts(t, strconv.Itoa(port)))
	if err != nil {
		t.Fatalf("ScanAll: %v", err)
	}
	if len(results) != want {
		t.Fatalf("got %d results, want one per address of localhost (%d)", len(results), want)
	}
	for _, r := range results {
		if r.Host != "localhost" {
			t.Errorf("Host = %q, want %q", r.Host, "localhost")
		}
		if r.IP == nil {
			t.Errorf("%v: IP is nil", r)
		}
		if r.IP.Equal(net.IPv4(127, 0, 0, 1)) && r.State != StateOpen {
			t.Errorf("127.0.0.1 came back as %v (%v), want %v", r.State, r.Err, StateOpen)
		}
	}
}
