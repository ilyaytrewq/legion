package portscan

import (
	"net"
	"strconv"
	"strings"
	"time"
)

// Result is the outcome for one requested port and, when resolution
// succeeded, one concrete address.
type Result struct {
	Host     string // Original target string supplied to Scan.
	IP       net.IP // Copy of the probed IP, or nil when no address was resolved.
	Zone     string // IPv6 zone, when present.
	Port     uint16
	State    State
	Duration time.Duration // Time spent in the TCP attempt, excluding queueing and DNS.
	Err      error         // Nil for StateOpen; wrapped underlying errors are read-only.
}

// String renders a result as a single human-readable line.
func (r Result) String() string {
	var b strings.Builder
	ip := r.IP.String()
	if r.IP != nil && r.IP.To4() == nil && r.Zone != "" {
		ip += "%" + r.Zone
	}
	port := strconv.FormatUint(uint64(r.Port), 10)

	if r.IP != nil && ip == r.Host && r.Port != 0 {
		b.WriteString(net.JoinHostPort(ip, port))
	} else {
		b.WriteString(r.Host)
		if r.IP != nil && ip != r.Host {
			b.WriteString(" (")
			if r.IP.To4() == nil && r.Port != 0 {
				b.WriteByte('[')
				b.WriteString(ip)
				b.WriteByte(']')
			} else {
				b.WriteString(ip)
			}
			b.WriteByte(')')
		}
		if r.Port != 0 {
			b.WriteByte(':')
			b.WriteString(port)
		}
	}
	b.WriteByte(' ')
	b.WriteString(r.State.String())
	if r.Duration > 0 {
		b.WriteString(" (")
		b.WriteString(r.Duration.String())
		b.WriteByte(')')
	}
	if r.Err != nil {
		b.WriteString(": ")
		b.WriteString(r.Err.Error())
	}
	return b.String()
}
