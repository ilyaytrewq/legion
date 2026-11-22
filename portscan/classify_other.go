//go:build !unix && !windows

package portscan

func classifySyscallErr(error) (State, bool) { return StateUnknown, false }

func isResourceErr(error) bool { return false }
