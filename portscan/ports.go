package portscan

import (
	"fmt"
	"iter"
	"math/bits"
	"strconv"
	"strings"
)

const (
	minPort   = 1
	maxPort   = 65535
	portWords = (maxPort + 1) / 64
)

// PortSet is an immutable set of TCP ports.
type PortSet struct {
	bits *[portWords]uint64
	n    int
}

func checkPort(port int) error {
	if port < minPort || port > maxPort {
		return fmt.Errorf("%w: %d", ErrInvalidPort, port)
	}
	return nil
}

func set(bits *[portWords]uint64, port int) bool {
	word, mask := port/64, uint64(1)<<(port%64)
	if bits[word]&mask != 0 {
		return false
	}
	bits[word] |= mask
	return true
}

// Range returns the set of all ports from from to to inclusive.
func Range(from, to int) (PortSet, error) {
	if err := checkPort(from); err != nil {
		return PortSet{}, err
	}
	if err := checkPort(to); err != nil {
		return PortSet{}, err
	}
	if from > to {
		return PortSet{}, fmt.Errorf("%w: %d-%d", ErrInvalidPortRange, from, to)
	}
	b := new([portWords]uint64)
	for p := from; p <= to; p++ {
		set(b, p)
	}
	return PortSet{bits: b, n: to - from + 1}, nil
}

// List returns the set of the given ports.
func List(ports ...int) (PortSet, error) {
	if len(ports) == 0 {
		return PortSet{}, ErrNoPorts
	}
	b := new([portWords]uint64)
	n := 0
	for _, p := range ports {
		if err := checkPort(p); err != nil {
			return PortSet{}, err
		}
		if set(b, p) {
			n++
		}
	}
	return PortSet{bits: b, n: n}, nil
}

// Union returns the union of the given sets.
func Union(sets ...PortSet) PortSet {
	b := new([portWords]uint64)
	for _, s := range sets {
		if s.bits == nil {
			continue
		}
		for i, w := range s.bits {
			b[i] |= w
		}
	}
	n := 0
	for _, w := range b {
		n += bits.OnesCount64(w)
	}
	if n == 0 {
		return PortSet{}
	}
	return PortSet{bits: b, n: n}
}

// ParsePorts parses a textual port specification such as "22,80,443,8000-9000".
// Empty input returns ErrNoPorts. Malformed or out-of-bounds endpoints match
// ErrInvalidPort; a range with valid but reversed endpoints matches ErrInvalidPortRange.
func ParsePorts(spec string) (PortSet, error) {
	if strings.TrimSpace(spec) == "" {
		return PortSet{}, ErrNoPorts
	}
	b := new([portWords]uint64)
	n := 0
	for item := range strings.SplitSeq(spec, ",") {
		item = strings.TrimSpace(item)
		lo, hi, isRange := strings.Cut(item, "-")
		from, err := parsePort(lo)
		if err != nil {
			return PortSet{}, err
		}
		to := from
		if isRange {
			if to, err = parsePort(hi); err != nil {
				return PortSet{}, err
			}
			if from > to {
				return PortSet{}, fmt.Errorf("%w: %q", ErrInvalidPortRange, item)
			}
		}
		for p := from; p <= to; p++ {
			if set(b, p) {
				n++
			}
		}
	}
	return PortSet{bits: b, n: n}, nil
}

func parsePort(s string) (int, error) {
	s = strings.TrimSpace(s)
	v, err := strconv.ParseUint(s, 10, 64)
	if err != nil || v < minPort || v > maxPort {
		return 0, fmt.Errorf("%w: %q", ErrInvalidPort, s)
	}
	return int(v), nil
}

// Len returns the number of ports in the set.
func (p PortSet) Len() int { return p.n }

// String returns the canonical specification of the set, or an empty string
// for an empty set.
func (p PortSet) String() string {
	var b strings.Builder
	runStart, runEnd := -1, -1
	flush := func() {
		if runStart < 0 {
			return
		}
		if b.Len() > 0 {
			b.WriteByte(',')
		}
		b.WriteString(strconv.Itoa(runStart))
		if runEnd != runStart {
			b.WriteByte('-')
			b.WriteString(strconv.Itoa(runEnd))
		}
	}
	for port := range p.all() {
		switch {
		case runStart < 0:
			runStart, runEnd = int(port), int(port)
		case int(port) == runEnd+1:
			runEnd = int(port)
		default:
			flush()
			runStart, runEnd = int(port), int(port)
		}
	}
	flush()
	return b.String()
}

func (p PortSet) all() iter.Seq[uint16] {
	return func(yield func(uint16) bool) {
		if p.bits == nil {
			return
		}
		for i, w := range p.bits {
			for w != 0 {
				bit := bits.TrailingZeros64(w)
				w &^= 1 << uint(bit)
				if !yield(uint16(i*64 + bit)) {
					return
				}
			}
		}
	}
}
