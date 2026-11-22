package portscan

import (
	"context"
	"errors"
	"iter"
	"net"
	"net/netip"
	"slices"
	"strings"
	"unicode"
)

type targetKind uint8

const (
	kindInvalid targetKind = iota
	kindAddr
	kindPrefix
	kindName
)

const maxPrefixHostBits = 16

var (
	errPrefixTooLarge    = errors.New("portscan: CIDR prefix contains more than 65536 addresses")
	errUnspecifiedTarget = errors.New("portscan: unspecified IP is not a scan target")
)

type target struct {
	raw    string
	kind   targetKind
	addr   net.IPAddr
	prefix netip.Prefix
}

func parseTargets(ctx context.Context, hosts []string) ([]target, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	// Reserve enough for common inputs without allocating for every duplicate
	// up front or committing to the entire input before observing cancellation.
	initial := min(len(hosts), 256)
	seen := make(map[string]struct{}, initial)
	targets := make([]target, 0, initial)
	var errs []error
	for _, host := range hosts {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if _, dup := seen[host]; dup {
			continue
		}
		seen[host] = struct{}{}
		t, err := parseTarget(host)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		targets = append(targets, t)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if len(errs) > 0 {
		return nil, errors.Join(errs...)
	}
	return targets, nil
}

func parseTarget(raw string) (target, error) {
	if raw == "" {
		return target{}, &TargetError{Target: raw, Err: errEmptyTarget}
	}
	if strings.ContainsAny(raw, " \t\r\n\v\f") {
		return target{}, &TargetError{Target: raw, Err: errInvalidTarget}
	}
	if strings.Contains(raw, "/") {
		prefix, err := netip.ParsePrefix(raw)
		if err != nil {
			return target{}, &TargetError{Target: raw, Err: err}
		}
		if prefix.Addr().BitLen()-prefix.Bits() > maxPrefixHostBits {
			return target{}, &TargetError{Target: raw, Err: errPrefixTooLarge}
		}
		prefix = prefix.Masked()
		if prefix.Bits() == prefix.Addr().BitLen() && prefix.Addr().Unmap().IsUnspecified() {
			return target{}, &TargetError{Target: raw, Err: errUnspecifiedTarget}
		}
		return target{raw: raw, kind: kindPrefix, prefix: prefix}, nil
	}
	if addr, err := netip.ParseAddr(raw); err == nil {
		if !validIPv6Zone(addr.Zone()) || (addr.Is4In6() && addr.Zone() != "") {
			return target{}, &TargetError{Target: raw, Err: errInvalidTarget}
		}
		addr = addr.Unmap()
		if addr.IsUnspecified() {
			return target{}, &TargetError{Target: raw, Err: errUnspecifiedTarget}
		}
		return target{
			raw:  raw,
			kind: kindAddr,
			addr: net.IPAddr{IP: addr.AsSlice(), Zone: addr.Zone()},
		}, nil
	}
	if !isDNSName(raw) {
		return target{}, &TargetError{Target: raw, Err: errInvalidTarget}
	}
	return target{raw: raw, kind: kindName}, nil
}

func isDNSName(s string) bool {
	name := strings.TrimSuffix(s, ".")
	if name == "" || len(name) > 253 {
		return false
	}
	var hasNonDigit bool
	for label := range strings.SplitSeq(name, ".") {
		if len(label) == 0 || len(label) > 63 {
			return false
		}
		if label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for i := 0; i < len(label); i++ {
			c := label[i]
			switch {
			case isASCIIDigit(c):
			case isASCIILetter(c), c == '-', c == '_':
				hasNonDigit = true
			default:
				return false
			}
		}
	}
	// Do not pass misspelled or abbreviated decimal IP addresses to DNS.
	return hasNonDigit
}

func validIPv6Zone(zone string) bool {
	// Brackets and '%' interfere with host:port or zone parsing. A slash
	// would be a CIDR delimiter in a literal target.
	return !strings.ContainsAny(zone, "[]%/") && strings.IndexFunc(zone, func(r rune) bool {
		return unicode.IsSpace(r) || unicode.IsControl(r)
	}) < 0
}

type resolved struct {
	target target
	addrs  iter.Seq[net.IPAddr]
	err    error
}

func (t target) resolve(ctx context.Context, res Resolver, firstAddrOnly bool) resolved {
	switch t.kind {
	case kindAddr:
		return resolved{target: t, addrs: slices.Values([]net.IPAddr{t.addr})}
	case kindPrefix:
		return resolved{target: t, addrs: prefixAddrs(t.prefix)}
	case kindName:
		return t.lookup(ctx, res, firstAddrOnly)
	default:
		return resolved{target: t, err: errUnknownTargetKind}
	}
}

func (t target) lookup(ctx context.Context, res Resolver, firstAddrOnly bool) resolved {
	addrs, err := res.LookupIPAddr(ctx, t.raw)
	if err != nil {
		return resolved{target: t, err: err}
	}
	addrs = dedupAddrs(addrs)
	if len(addrs) == 0 {
		return resolved{target: t, err: errNoAddresses}
	}
	if firstAddrOnly {
		addrs = addrs[:1]
	}
	return resolved{target: t, addrs: slices.Values(addrs)}
}

func prefixAddrs(prefix netip.Prefix) iter.Seq[net.IPAddr] {
	return func(yield func(net.IPAddr) bool) {
		for addr := prefix.Addr(); prefix.Contains(addr); addr = addr.Next() {
			ip := addr.Unmap()
			if ip.IsUnspecified() {
				continue
			}
			if !yield(net.IPAddr{IP: ip.AsSlice()}) {
				return
			}
		}
	}
}

func dedupAddrs(addrs []net.IPAddr) []net.IPAddr {
	out := make([]net.IPAddr, 0, len(addrs))
	seen := make(map[netip.Addr]struct{}, len(addrs))
	for _, a := range addrs {
		addr, ok := netip.AddrFromSlice(a.IP)
		if !ok {
			continue
		}
		addr = addr.Unmap()
		if addr.IsUnspecified() {
			continue
		}
		if addr.Is4() {
			a.Zone = ""
		} else if !validIPv6Zone(a.Zone) {
			continue
		}
		key := addr.WithZone(a.Zone)
		if _, dup := seen[key]; dup {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, net.IPAddr{IP: addr.AsSlice(), Zone: a.Zone})
	}
	return out
}
