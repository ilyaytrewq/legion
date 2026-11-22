package portscan

import (
	"context"
	"net"
	"slices"
	"strconv"
	"time"
)

func (s *Scanner) work(ctx context.Context, jobs <-chan job, results chan<- Result) {
	for j := range jobs {
		if j.preErr != nil {
			if !sendResult(ctx, results, Result{
				Host:  j.host,
				Port:  j.port,
				State: StateUnresolved,
				Err:   j.preErr,
			}) {
				return
			}
			if ctx.Err() != nil {
				return
			}
			continue
		}

		if ctx.Err() != nil {
			return
		}
		if !s.probe(ctx, j, results) {
			return
		}
	}
}

func (s *Scanner) probe(ctx context.Context, j job, results chan<- Result) bool {
	if !s.sem.acquire(ctx) {
		return false
	}

	dialCtx, cancel := context.WithTimeoutCause(ctx, s.connectTimeout, errConnectTimeout)

	address := net.JoinHostPort(j.addr.String(), strconv.FormatUint(uint64(j.port), 10))

	start := time.Now()
	conn, err := s.dialer.DialContext(dialCtx, "tcp", address)
	finishedAt := time.Now()
	nilConn := isNilInterface(conn)
	if err == nil && nilConn {
		err = errNilConnection
	}
	state := classify(dialCtx, err, err != nil && reachedCallerDeadline(ctx, dialCtx, finishedAt))
	cancel()

	if !nilConn {
		_ = conn.Close()
	}
	s.sem.release()

	result := Result{
		Host:     j.host,
		IP:       slices.Clone(j.addr.IP),
		Zone:     j.addr.Zone,
		Port:     j.port,
		State:    state,
		Duration: finishedAt.Sub(start),
	}
	if err != nil {
		result.Err = reportErr(err)
	}
	return sendResult(ctx, results, result)
}
