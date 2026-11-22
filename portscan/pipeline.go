package portscan

import (
	"context"
	"net"
	"sync"
)

type job struct {
	host string
	addr net.IPAddr
	port uint16

	preErr *TargetError
}

func (s *Scanner) run(ctx context.Context, targets []target, ports PortSet) <-chan Result {
	workers := s.probeWorkerCount(targets, ports.Len())
	targetsCh, feedDone := feedTargets(ctx, targets)
	resolvedCh, resolversDone := s.resolveTargets(ctx, targetsCh, min(len(targets), cap(s.resolverSem)))
	jobs, dispatchDone := dispatchJobs(ctx, resolvedCh, ports)
	return s.probeJobs(ctx, jobs, workers, feedDone, resolversDone, dispatchDone)
}

// probeWorkerCount caps workers only when the maximum number of jobs is known.
// The count saturates at concurrency, without overflowing the address or job total.
func (s *Scanner) probeWorkerCount(targets []target, portCount int) int {
	addressLimit := 1 + (s.concurrency-1)/portCount
	addresses := 0
	for _, t := range targets {
		count := 1 // A literal or a resolution failure produces one job per port.
		switch t.kind {
		case kindPrefix:
			count = 1 << (t.prefix.Addr().BitLen() - t.prefix.Bits())
		case kindName:
			if !s.firstAddrOnly {
				return s.concurrency
			}
		}
		if count >= addressLimit-addresses {
			return s.concurrency
		}
		addresses += count
	}
	return addresses * portCount
}

func feedTargets(ctx context.Context, targets []target) (<-chan target, <-chan struct{}) {
	out := make(chan target)
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer close(out)
		for _, t := range targets {
			if !submit(ctx, out, t) {
				return
			}
		}
	}()
	return out, done
}

type limitedResolver struct {
	resolver Resolver
	sem      semaphore
}

func (r limitedResolver) LookupIPAddr(ctx context.Context, host string) ([]net.IPAddr, error) {
	if !r.sem.acquire(ctx) {
		return nil, ctx.Err()
	}
	defer r.sem.release()
	return r.resolver.LookupIPAddr(ctx, host)
}

func (s *Scanner) resolveTargets(ctx context.Context, in <-chan target, workers int) (<-chan resolved, <-chan struct{}) {
	out := make(chan resolved)
	done := make(chan struct{})
	resolver := limitedResolver{resolver: s.resolver, sem: s.resolverSem}

	var wg sync.WaitGroup
	for range workers {
		wg.Go(func() {
			for t := range in {
				if ctx.Err() != nil {
					return
				}
				if !submit(ctx, out, t.resolve(ctx, resolver, s.firstAddrOnly)) {
					return
				}
			}
		})
	}
	go func() {
		wg.Wait()
		close(out)
		close(done)
	}()
	return out, done
}

func dispatchJobs(ctx context.Context, in <-chan resolved, ports PortSet) (<-chan job, <-chan struct{}) {
	out := make(chan job)
	done := make(chan struct{})
	go func() {
		dispatch(ctx, in, out, ports)
		close(done)
	}()
	return out, done
}

func (s *Scanner) probeJobs(ctx context.Context, in <-chan job, workers int, upstream ...<-chan struct{}) <-chan Result {
	out := make(chan Result)
	go func() {
		defer close(out)
		var wg sync.WaitGroup
		for range workers {
			wg.Go(func() {
				s.work(ctx, in, out)
			})
		}
		wg.Wait()
		for _, done := range upstream {
			<-done
		}
	}()
	return out
}

func dispatch(ctx context.Context, in <-chan resolved, out chan<- job, ports PortSet) {
	defer close(out)
	for r := range in {
		if r.err != nil {
			for port := range ports.all() {
				j := job{
					host: r.target.raw,
					port: port,
					// Each result owns its wrapper; the resolver's error is shared
					// and must be treated as immutable.
					preErr: &TargetError{Target: r.target.raw, Err: r.err},
				}
				if !submit(ctx, out, j) {
					return
				}
			}
			continue
		}
		for addr := range r.addrs {
			for port := range ports.all() {
				if !submit(ctx, out, job{host: r.target.raw, addr: addr, port: port}) {
					return
				}
			}
		}
	}
}

// submit rejects work if cancellation is already observable, even if out is
// ready. A send already racing with cancellation may still complete.
func submit[T any](ctx context.Context, out chan<- T, v T) bool {
	select {
	case <-ctx.Done():
		return false
	default:
	}
	select {
	case out <- v:
		return true
	case <-ctx.Done():
		return false
	}
}

// sendResult prefers delivering completed results if the reader is ready,
// but will not block indefinitely after cancellation.
func sendResult(ctx context.Context, out chan<- Result, result Result) bool {
	select {
	case out <- result:
		return true
	default:
	}
	select {
	case out <- result:
		return true
	case <-ctx.Done():
		return false
	}
}
