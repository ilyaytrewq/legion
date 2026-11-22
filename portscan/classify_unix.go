//go:build unix

package portscan

import (
	"errors"
	"syscall"
)

func classifySyscallErr(err error) (State, bool) {
	var errno syscall.Errno
	if !errors.As(err, &errno) {
		return StateUnknown, false
	}
	switch errno {
	case syscall.ECONNREFUSED:
		return StateClosed, true

	case syscall.EHOSTUNREACH, syscall.ENETUNREACH,
		syscall.EHOSTDOWN, syscall.ENETDOWN:
		return StateUnreachable, true

	case syscall.ETIMEDOUT:
		return StateTimeout, true

	case syscall.EMFILE, syscall.ENFILE, syscall.ENOBUFS, syscall.ENOMEM,
		syscall.EAGAIN, syscall.EAFNOSUPPORT, syscall.ECONNABORTED, syscall.ECONNRESET,
		syscall.ENETRESET, syscall.EPROTOTYPE, syscall.EINVAL, syscall.EACCES,
		syscall.EPERM, syscall.EADDRNOTAVAIL:
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
	case syscall.EMFILE, syscall.ENFILE, syscall.ENOBUFS, syscall.ENOMEM,
		syscall.EAGAIN:
		return true
	}
	return false
}
