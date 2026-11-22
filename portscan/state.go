package portscan

import (
	"errors"
	"strconv"
)

// State is the outcome of one requested port check.
type State uint8

const (
	// StateUnknown is the zero value of State.
	StateUnknown State = iota

	// StateOpen means the TCP handshake completed.
	StateOpen

	// StateClosed means the peer refused the connection.
	StateClosed

	// StateTimeout means the attempt produced no answer within the timeout.
	StateTimeout

	// StateUnreachable means the host or network was unreachable.
	StateUnreachable

	// StateCanceled means the caller's context ended before the attempt finished.
	StateCanceled

	// StateUnresolved means the target could not be resolved to any address.
	StateUnresolved

	// StateError means the attempt failed for a reason unrelated to the port.
	StateError
)

var stateNames = [...]string{
	StateUnknown:     "unknown",
	StateOpen:        "open",
	StateClosed:      "closed",
	StateTimeout:     "timeout",
	StateUnreachable: "unreachable",
	StateCanceled:    "canceled",
	StateUnresolved:  "unresolved",
	StateError:       "error",
}

// String returns the lower-case name of the state.
func (s State) String() string {
	if int(s) < len(stateNames) {
		return stateNames[s]
	}
	return "State(" + strconv.Itoa(int(s)) + ")"
}

var errInvalidState = errors.New("portscan: invalid state")

// MarshalText implements encoding.TextMarshaler.
func (s State) MarshalText() ([]byte, error) {
	if int(s) >= len(stateNames) {
		return nil, errInvalidState
	}
	return []byte(stateNames[s]), nil
}

// UnmarshalText implements encoding.TextUnmarshaler.
func (s *State) UnmarshalText(text []byte) error {
	for i, name := range stateNames {
		if name == string(text) {
			*s = State(i)
			return nil
		}
	}
	return errInvalidState
}
