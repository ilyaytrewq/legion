package portscan

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"slices"
	"strings"
	"testing"
)

func TestParseTarget(t *testing.T) {
	tests := []struct {
		name     string
		raw      string
		wantKind targetKind
		wantIP   string
		wantZone string
		wantErr  bool
	}{
		{name: "IPv4 literal", raw: "192.168.1.10", wantKind: kindAddr, wantIP: "192.168.1.10"},
		{name: "IPv6 literal", raw: "::1", wantKind: kindAddr, wantIP: "::1"},
		{name: "IPv6 full form", raw: "2001:db8::1", wantKind: kindAddr, wantIP: "2001:db8::1"},
		{name: "IPv6 with zone", raw: "fe80::1%en0", wantKind: kindAddr, wantIP: "fe80::1", wantZone: "en0"},
		{name: "IPv4-mapped IPv6", raw: "::ffff:1.2.3.4", wantKind: kindAddr, wantIP: "1.2.3.4"},

		{name: "DNS name", raw: "example.com", wantKind: kindName},
		{name: "fully qualified name", raw: "example.com.", wantKind: kindName},
		{name: "single label", raw: "localhost", wantKind: kindName},
		{name: "underscore label", raw: "my_host.example.com", wantKind: kindName},
		{name: "uppercase", raw: "Example.COM", wantKind: kindName},
		{name: "numeric labels mixed with hostname", raw: "123.45.example", wantKind: kindName},

		{name: "IPv4 prefix", raw: "10.0.0.0/24", wantKind: kindPrefix},
		{name: "IPv4 prefix with host bits", raw: "10.0.0.7/24", wantKind: kindPrefix},
		{name: "single host prefix", raw: "192.168.1.1/32", wantKind: kindPrefix},
		{name: "largest IPv4 prefix", raw: "10.0.0.0/16", wantKind: kindPrefix},
		{name: "IPv6 prefix", raw: "2001:db8::/120", wantKind: kindPrefix},
		{name: "largest IPv6 prefix", raw: "2001:db8::/112", wantKind: kindPrefix},

		{name: "empty", raw: "", wantErr: true},
		{name: "leading and trailing spaces", raw: " 1.2.3.4 ", wantErr: true},
		{name: "inner space", raw: "example .com", wantErr: true},
		{name: "tab", raw: "1.2.3.4\t", wantErr: true},
		{name: "host and port", raw: "example.com:80", wantErr: true},
		{name: "IP and port", raw: "1.2.3.4:80", wantErr: true},
		{name: "unterminated bracket", raw: "[::1", wantErr: true},
		{name: "bracketed IPv6", raw: "[::1]", wantErr: true},
		{name: "bracketed with port", raw: "[::1]:80", wantErr: true},
		{name: "empty zone", raw: "fe80::1%", wantErr: true},
		{name: "bracket in zone", raw: "fe80::1%]", wantErr: true},
		{name: "repeated zone delimiter", raw: "fe80::1%en0%en1", wantErr: true},
		{name: "control byte in zone", raw: "fe80::1%en\x00", wantErr: true},
		{name: "zone on IPv4", raw: "1.2.3.4%en0", wantErr: true},
		{name: "unspecified IPv4", raw: "0.0.0.0", wantErr: true},
		{name: "unspecified IPv6", raw: "::", wantErr: true},
		{name: "unspecified mapped IP", raw: "::ffff:0.0.0.0", wantErr: true},
		{name: "unspecified singleton IPv4", raw: "0.0.0.0/32", wantErr: true},
		{name: "unspecified singleton IPv6", raw: "::/128", wantErr: true},
		{name: "unspecified singleton mapped IP", raw: "::ffff:0.0.0.0/128", wantErr: true},
		{name: "out of range octets", raw: "300.1.2.3", wantErr: true},
		{name: "leading zero octets", raw: "01.2.3.4", wantErr: true},
		{name: "abbreviated dotted IP", raw: "127.1", wantErr: true},
		{name: "numeric only name", raw: "12345", wantErr: true},
		{name: "zone on IPv4-mapped IPv6", raw: "::ffff:1.2.3.4%en0", wantErr: true},
		{name: "URL", raw: "http://example.com", wantErr: true},
		{name: "double dot", raw: "example..com", wantErr: true},
		{name: "trailing double dot", raw: "example.com..", wantErr: true},
		{name: "root", raw: ".", wantErr: true},
		{name: "leading hyphen", raw: "-example.com", wantErr: true},
		{name: "trailing hyphen", raw: "example-.com", wantErr: true},
		{name: "label too long", raw: strings.Repeat("a", 64) + ".com", wantErr: true},
		{name: "name too long", raw: strings.Repeat("a.", 130) + "com", wantErr: true},
		{name: "prefix out of range", raw: "10.0.0.0/33", wantErr: true},
		{name: "IPv6 prefix out of range", raw: "2001:db8::/129", wantErr: true},
		{name: "prefix without address", raw: "/24", wantErr: true},
		{name: "prefix without length", raw: "10.0.0.0/", wantErr: true},
		{name: "name with prefix", raw: "example.com/24", wantErr: true},
		{name: "IPv4 prefix too large", raw: "10.0.0.0/15", wantErr: true},
		{name: "IPv6 prefix too large", raw: "2001:db8::/111", wantErr: true},
		{name: "wildcard", raw: "*.example.com", wantErr: true},
		{name: "non-ASCII", raw: "пример.рф", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseTarget(tt.raw)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("parseTarget(%q) = %+v, want an error", tt.raw, got)
				}
				var target *TargetError
				if !errors.As(err, &target) {
					t.Fatalf("parseTarget(%q) error = %v (%T), want *TargetError", tt.raw, err, err)
				}
				if target.Target != tt.raw {
					t.Errorf("TargetError.Target = %q, want %q", target.Target, tt.raw)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseTarget(%q): %v", tt.raw, err)
			}
			if got.kind != tt.wantKind {
				t.Fatalf("kind = %d, want %d", got.kind, tt.wantKind)
			}
			if got.raw != tt.raw {
				t.Errorf("raw = %q, want %q: the caller's string must be preserved", got.raw, tt.raw)
			}
			if tt.wantKind == kindAddr {
				if got.addr.IP.String() != tt.wantIP {
					t.Errorf("IP = %v, want %v", got.addr.IP, tt.wantIP)
				}
				if got.addr.Zone != tt.wantZone {
					t.Errorf("Zone = %q, want %q", got.addr.Zone, tt.wantZone)
				}
			}
		})
	}
}

func TestParseTargetsDeduplicates(t *testing.T) {
	targets, err := parseTargets(t.Context(), []string{
		"1.2.3.4", "example.com", "1.2.3.4", "10.0.0.0/24", "example.com", "1.2.3.4",
	})
	if err != nil {
		t.Fatalf("parseTargets: %v", err)
	}
	var raws []string
	for _, target := range targets {
		raws = append(raws, target.raw)
	}
	want := []string{"1.2.3.4", "example.com", "10.0.0.0/24"}
	if !slices.Equal(raws, want) {
		t.Errorf("targets = %v, want %v (deduplicated, input order kept)", raws, want)
	}
}

func TestParseTargetsKeepsDistinctStrings(t *testing.T) {
	targets, err := parseTargets(t.Context(), []string{"a.example.com", "b.example.com"})
	if err != nil {
		t.Fatalf("parseTargets: %v", err)
	}
	if len(targets) != 2 {
		t.Fatalf("got %d targets, want 2", len(targets))
	}
}

func TestParseTargetsReportsEveryBadTarget(t *testing.T) {
	_, err := parseTargets(t.Context(), []string{"1.2.3.4", "", "example.com:80", "", "10.0.0.0/33"})
	if err == nil {
		t.Fatal("parseTargets succeeded, want an error")
	}
	joined, ok := err.(interface{ Unwrap() []error })
	if !ok {
		t.Fatalf("error %T does not unwrap to several errors", err)
	}
	if got := len(joined.Unwrap()); got != 3 {
		t.Errorf("got %d errors, want 3: %v", got, err)
	}
	for _, raw := range []string{"", "example.com:80", "10.0.0.0/33"} {
		if !strings.Contains(err.Error(), raw) && raw != "" {
			t.Errorf("aggregate error does not mention %q: %v", raw, err)
		}
	}
}

// parseCancelContext triggers a real cancellation during an Err check without
// relying on input size, timers, or goroutine scheduling.
type parseCancelContext struct {
	context.Context
	after  int
	cancel context.CancelFunc
}

func (c *parseCancelContext) Err() error {
	c.after--
	if c.after == 0 {
		c.cancel()
	}
	return c.Context.Err()
}

func TestParseTargetsStopsOnCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	ctxOnParse := &parseCancelContext{Context: ctx, after: 3, cancel: cancel}
	got, err := parseTargets(ctxOnParse, []string{"192.0.2.1", "192.0.2.2", "host.example"})
	if got != nil || !errors.Is(err, context.Canceled) {
		t.Fatalf("parseTargets = %v, %v; want nil, context.Canceled", got, err)
	}
}

func TestScanRejectsUndialableLiteralSynchronously(t *testing.T) {
	s := mustScanner(t, WithDialer(&fakeDialer{}))
	ports := mustPorts(t, "80")
	for _, raw := range []string{"fe80::1%]", "0.0.0.0", "::", "::ffff:0.0.0.0"} {
		t.Run(raw, func(t *testing.T) {
			ch, err := s.Scan(t.Context(), []string{raw}, ports)
			var targetErr *TargetError
			if ch != nil || !errors.As(err, &targetErr) || targetErr.Target != raw {
				t.Fatalf("Scan returned %v, %v; want nil channel and TargetError for %q", ch, err, raw)
			}
		})
	}
}

func TestPrefixAddrs(t *testing.T) {
	tests := []struct {
		prefix string
		want   []string
	}{
		{prefix: "10.0.0.0/30", want: []string{"10.0.0.0", "10.0.0.1", "10.0.0.2", "10.0.0.3"}},
		{prefix: "10.0.0.6/30", want: []string{"10.0.0.4", "10.0.0.5", "10.0.0.6", "10.0.0.7"}},
		{prefix: "192.168.1.1/32", want: []string{"192.168.1.1"}},
		{prefix: "2001:db8::/126", want: []string{"2001:db8::", "2001:db8::1", "2001:db8::2", "2001:db8::3"}},
		{prefix: "::1/128", want: []string{"::1"}},
		{prefix: "0.0.0.2/30", want: []string{"0.0.0.1", "0.0.0.2", "0.0.0.3"}},
		{prefix: "::/126", want: []string{"::1", "::2", "::3"}},
		{prefix: "::ffff:0.0.0.0/127", want: []string{"0.0.0.1"}},
		{prefix: "255.255.255.252/30", want: []string{"255.255.255.252", "255.255.255.253", "255.255.255.254", "255.255.255.255"}},
	}
	for _, tt := range tests {
		t.Run(tt.prefix, func(t *testing.T) {
			target, err := parseTarget(tt.prefix)
			if err != nil {
				t.Fatalf("parseTarget(%q): %v", tt.prefix, err)
			}
			res := &fakeResolver{}
			var got []string
			for addr := range target.resolve(t.Context(), res, false).addrs {
				got = append(got, addr.IP.String())
			}
			if !slices.Equal(got, tt.want) {
				t.Errorf("addresses = %v, want %v", got, tt.want)
			}
			if n := len(res.lookups()); n != 0 {
				t.Errorf("resolver was called %d times for a CIDR prefix", n)
			}
		})
	}
}

func TestPrefixAddrsIsLazy(t *testing.T) {
	target, err := parseTarget("10.0.0.0/16")
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for addr := range target.resolve(t.Context(), &fakeResolver{}, false).addrs {
		got = append(got, addr.IP.String())
		if len(got) == 3 {
			break
		}
	}
	want := []string{"10.0.0.0", "10.0.0.1", "10.0.0.2"}
	if !slices.Equal(got, want) {
		t.Errorf("addresses = %v, want %v", got, want)
	}
}

func TestParseTargetRejectsOversizedPrefix(t *testing.T) {
	for _, raw := range []string{"0.0.0.0/0", "10.0.0.0/15", "::/0", "2001:db8::/111"} {
		t.Run(raw, func(t *testing.T) {
			_, err := parseTarget(raw)
			var targetErr *TargetError
			if !errors.As(err, &targetErr) {
				t.Fatalf("parseTarget(%q) error = %v, want *TargetError", raw, err)
			}
			if !errors.Is(err, errPrefixTooLarge) {
				t.Errorf("parseTarget(%q) error = %v, want %v", raw, err, errPrefixTooLarge)
			}
		})
	}
}

func TestResolve(t *testing.T) {
	ctx := t.Context()

	t.Run("literal needs no lookup", func(t *testing.T) {
		res := &fakeResolver{}
		target, err := parseTarget("1.2.3.4")
		if err != nil {
			t.Fatal(err)
		}
		got := target.resolve(ctx, res, false)
		if got.err != nil {
			t.Fatalf("resolve: %v", got.err)
		}
		if addrs := slices.Collect(got.addrs); len(addrs) != 1 || addrs[0].IP.String() != "1.2.3.4" {
			t.Errorf("addrs = %v, want [1.2.3.4]", addrs)
		}
		if n := len(res.lookups()); n != 0 {
			t.Errorf("resolver was called %d times for an IP literal", n)
		}
	})

	t.Run("name with several addresses", func(t *testing.T) {
		res := newFakeResolver(map[string][]string{
			"multi.example.com": {"192.0.2.1", "192.0.2.2", "2001:db8::1"},
		})
		target, err := parseTarget("multi.example.com")
		if err != nil {
			t.Fatal(err)
		}
		got := target.resolve(ctx, res, false)
		if got.err != nil {
			t.Fatalf("resolve: %v", got.err)
		}
		if addrs := slices.Collect(got.addrs); len(addrs) != 3 {
			t.Errorf("addrs = %v, want 3 addresses", addrs)
		}

		first := slices.Collect(target.resolve(ctx, res, true).addrs)
		if len(first) != 1 || first[0].IP.String() != "192.0.2.1" {
			t.Errorf("WithFirstAddrOnly gave %v, want [192.0.2.1]", first)
		}
	})

	t.Run("repeated addresses collapse", func(t *testing.T) {
		res := newFakeResolver(map[string][]string{
			"dup.example.com": {"192.0.2.1", "192.0.2.1", "::ffff:192.0.2.1", "192.0.2.2"},
		})
		target, err := parseTarget("dup.example.com")
		if err != nil {
			t.Fatal(err)
		}
		got := target.resolve(ctx, res, false)
		if addrs := slices.Collect(got.addrs); len(addrs) != 2 {
			t.Errorf("addrs = %v, want 2 distinct addresses", addrs)
		}
	})

	t.Run("lookup failure", func(t *testing.T) {
		res := &fakeResolver{err: &net.DNSError{Err: "no such host", Name: "nx.invalid", IsNotFound: true}}
		target, err := parseTarget("nx.invalid")
		if err != nil {
			t.Fatal(err)
		}
		got := target.resolve(ctx, res, false)
		var dnsErr *net.DNSError
		if !errors.As(got.err, &dnsErr) {
			t.Fatalf("err = %v, want *net.DNSError", got.err)
		}
	})

	t.Run("empty answer", func(t *testing.T) {
		res := newFakeResolver(map[string][]string{"empty.example.com": {}})
		target, err := parseTarget("empty.example.com")
		if err != nil {
			t.Fatal(err)
		}
		if got := target.resolve(ctx, res, false); !errors.Is(got.err, errNoAddresses) {
			t.Errorf("err = %v, want %v", got.err, errNoAddresses)
		}
	})

	t.Run("cancelled lookup", func(t *testing.T) {
		canceled, cancel := context.WithCancel(ctx)
		cancel()
		res := &fakeResolver{err: errors.New("operation was canceled")}
		target, err := parseTarget("slow.example.com")
		if err != nil {
			t.Fatal(err)
		}
		got := target.resolve(canceled, res, false)
		if got.err == nil {
			t.Fatal("resolve succeeded, want an error")
		}
	})
}

func TestResolveRejectsUnknownKind(t *testing.T) {
	res := &fakeResolver{}
	for _, tt := range []struct {
		name   string
		target target
	}{
		{name: "zero value", target: target{raw: "192.0.2.1"}},
		{name: "out of range", target: target{raw: "192.0.2.1", kind: kindName + 1}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.target.resolve(t.Context(), res, false)
			if !errors.Is(got.err, errUnknownTargetKind) {
				t.Errorf("err = %v, want %v", got.err, errUnknownTargetKind)
			}
		})
	}
	if n := len(res.lookups()); n != 0 {
		t.Errorf("the resolver was called %d times for kinds that have no dispatch arm", n)
	}
}

func TestDedupAddrsNormalizes(t *testing.T) {
	got := dedupAddrs([]net.IPAddr{
		{IP: net.ParseIP("1.2.3.4")},
		{IP: net.ParseIP("::1")},
		{IP: net.IP{1, 2, 3}},
	})
	if len(got) != 2 {
		t.Fatalf("got %d addresses, want 2", len(got))
	}
	if n := len(got[0].IP); n != net.IPv4len {
		t.Errorf("IPv4 normalised to %d bytes, want %d", n, net.IPv4len)
	}
	if n := len(got[1].IP); n != net.IPv6len {
		t.Errorf("IPv6 normalised to %d bytes, want %d", n, net.IPv6len)
	}
}

func TestResolveOwnsResolverAddresses(t *testing.T) {
	source := net.ParseIP("192.0.2.1")
	resolver := &fakeResolver{addrs: map[string][]net.IPAddr{
		"owned.example.com": {{IP: source}},
	}}
	target, err := parseTarget("owned.example.com")
	if err != nil {
		t.Fatal(err)
	}

	got := target.resolve(t.Context(), resolver, false)
	if got.err != nil {
		t.Fatalf("resolve: %v", got.err)
	}
	for i := range source {
		source[i] = 0
	}
	if gotIP := slices.Collect(got.addrs)[0].IP.String(); gotIP != "192.0.2.1" {
		t.Errorf("resolved IP changed with resolver-owned storage: got %q", gotIP)
	}
}

func TestScanDropsUnusableResolverAddresses(t *testing.T) {
	bad := []net.IPAddr{
		{IP: net.IPv4zero},
		{IP: net.IPv6unspecified},
		{IP: net.ParseIP("fe80::1"), Zone: "]"},
	}
	good := net.ParseIP("192.0.2.1")
	resolver := &fakeResolver{addrs: map[string][]net.IPAddr{
		"only-bad.example": bad,
		"mixed.example":    append(slices.Clone(bad), net.IPAddr{IP: good}),
	}}
	dialer := &fakeDialer{}
	s := mustScanner(t, WithResolver(resolver), WithDialer(dialer), WithFirstAddrOnly())
	results, err := s.ScanAll(t.Context(), []string{"only-bad.example", "mixed.example"}, mustPorts(t, "80"))
	if err != nil || len(results) != 2 {
		t.Fatalf("ScanAll = %v, %v; want exactly two results", results, err)
	}
	for _, r := range results {
		switch r.Host {
		case "only-bad.example":
			if r.State != StateUnresolved || r.IP != nil || !errors.Is(r.Err, errNoAddresses) {
				t.Errorf("bad-only result = %v; want unresolved with no usable addresses", r)
			}
		case "mixed.example":
			if r.State != StateOpen || !r.IP.Equal(good) {
				t.Errorf("mixed result = %v; want the first usable address open", r)
			}
		default:
			t.Errorf("unexpected host %q", r.Host)
		}
	}
	if got := dialer.attempts(); !slices.Equal(got, []string{"192.0.2.1:80"}) {
		t.Errorf("dialed %v; want only 192.0.2.1:80", got)
	}
}

func TestDedupAddrsDropsIPv4Zone(t *testing.T) {
	got := dedupAddrs([]net.IPAddr{
		{IP: net.ParseIP("192.0.2.1"), Zone: "invalid"},
		{IP: net.ParseIP("192.0.2.1")},
	})
	if len(got) != 1 {
		t.Fatalf("got %d addresses, want 1", len(got))
	}
	if got[0].IP.String() != "192.0.2.1" || got[0].Zone != "" {
		t.Errorf("address = %v zone %q, want unzoned IPv4", got[0].IP, got[0].Zone)
	}
}

func FuzzParseTarget(f *testing.F) {
	for _, seed := range []string{
		"", "localhost", "example.com.", "192.0.2.1", "300.1.2.3", "::1",
		"fe80::1%en0", "10.0.0.0/24", "10.0.0.0/15", "2001:db8::/120",
		"[::1]:80", "host:80", "example..com", "пример.рф", "\x00",
		"::ffff:1.2.3.4%en0", "fe80::1%en0%en1", "255.255.255.252/30",
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		got, err := parseTarget(raw)
		if err != nil {
			var targetErr *TargetError
			if !errors.As(err, &targetErr) {
				t.Fatalf("parseTarget(%q) error = %T, want *TargetError", raw, err)
			}
			return
		}
		if got.raw != raw {
			t.Fatalf("parseTarget(%q) preserved raw value as %q", raw, got.raw)
		}

		switch got.kind {
		case kindAddr:
			if n := len(got.addr.IP); n != net.IPv4len && n != net.IPv6len {
				t.Fatalf("parseTarget(%q) address has %d bytes", raw, n)
			}
			if got.addr.Zone != "" && got.addr.IP.To4() != nil {
				t.Fatalf("parseTarget(%q) retained zone %q on IPv4", raw, got.addr.Zone)
			}
			if got.prefix.IsValid() {
				t.Fatalf("parseTarget(%q) address also has a prefix", raw)
			}
		case kindPrefix:
			if !got.prefix.IsValid() {
				t.Fatalf("parseTarget(%q) prefix is invalid", raw)
			}
			if host := got.prefix.Addr().BitLen() - got.prefix.Bits(); host > maxPrefixHostBits {
				t.Fatalf("parseTarget(%q) accepted %d host bits", raw, host)
			}
		case kindName:
			if !isDNSName(raw) || strings.Contains(raw, "/") {
				t.Fatalf("parseTarget(%q) returned kindName for invalid syntax", raw)
			}
			if _, err := netip.ParseAddr(raw); err == nil {
				t.Fatalf("parseTarget(%q) returned kindName for an IP literal", raw)
			}
		default:
			t.Fatalf("parseTarget(%q) returned unknown kind %d", raw, got.kind)
		}
	})
}
