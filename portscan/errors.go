package portscan

import (
	"errors"
	"fmt"
)

var (
	// ErrNoTargets is returned when the target list is empty.
	ErrNoTargets = errors.New("portscan: no targets")

	// ErrNoPorts is returned when the port set is empty.
	ErrNoPorts = errors.New("portscan: empty port set")

	// ErrInvalidPort is returned when a port is malformed or outside [1, 65535].
	ErrInvalidPort = errors.New("portscan: invalid port")

	// ErrInvalidPortRange is returned when valid port endpoints are in reverse order.
	ErrInvalidPortRange = errors.New("portscan: invalid port range")

	// ErrResourceExhausted marks a failure caused by local resource exhaustion.
	ErrResourceExhausted = errors.New("portscan: local resource exhausted")
)

var (
	errNilContext        = errors.New("portscan: nil context")
	errNilOption         = errors.New("portscan: nil option")
	errEmptyTarget       = errors.New("portscan: empty target")
	errInvalidTarget     = errors.New("portscan: not an IP address, CIDR prefix or DNS name")
	errNoAddresses       = errors.New("portscan: resolved to no usable addresses")
	errUnknownTargetKind = errors.New("portscan: unknown target kind")
	errNilConnection     = errors.New("portscan: dialer returned a nil connection without an error")
	errConnectTimeout    = errors.New("portscan: connect timeout exceeded")
)

// TargetError attributes an error to one entry of the target list.
type TargetError struct {
	Target string
	Err    error
}

func (e *TargetError) Error() string {
	return fmt.Sprintf("portscan: target %q: %v", e.Target, e.Err)
}

// Unwrap returns e.Err.
func (e *TargetError) Unwrap() error { return e.Err }
