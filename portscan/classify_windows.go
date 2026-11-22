//go:build windows

package portscan

import (
	"errors"
	"syscall"
)

const (
	wsaeaccess       syscall.Errno = 10013
	wsaemfile        syscall.Errno = 10024
	wsaeprototype    syscall.Errno = 10041
	wsaeafnosupport  syscall.Errno = 10047
	wsaeaddrnotavail syscall.Errno = 10049
	wsaenetdown      syscall.Errno = 10050
	wsaenetunreach   syscall.Errno = 10051
	wsaenetreset     syscall.Errno = 10052
	wsaeconnaborted  syscall.Errno = 10053
	wsaeconnreset    syscall.Errno = 10054
	wsaenobufs       syscall.Errno = 10055
	wsaetimedout     syscall.Errno = 10060
	wsaeconnrefused  syscall.Errno = 10061
	wsaehostdown     syscall.Errno = 10064
	wsaehostunreach  syscall.Errno = 10065
)

func classifySyscallErr(err error) (State, bool) {
	var errno syscall.Errno
	if !errors.As(err, &errno) {
		return StateUnknown, false
	}
	switch errno {
	case wsaeconnrefused:
		return StateClosed, true

	case wsaehostunreach, wsaenetunreach, wsaehostdown, wsaenetdown:
		return StateUnreachable, true

	case wsaetimedout:
		return StateTimeout, true

	case wsaemfile, wsaenobufs, wsaeafnosupport, wsaeconnaborted,
		wsaeconnreset, wsaenetreset, wsaeprototype, wsaeaccess, wsaeaddrnotavail:
		return StateError, true
	}
	return StateUnknown, false
}

func isResourceErr(err error) bool {
	var errno syscall.Errno
	if !errors.As(err, &errno) {
		return false
	}
	switch errno {
	case wsaemfile, wsaenobufs:
		return true
	}
	return false
}
