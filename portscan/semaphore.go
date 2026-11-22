package portscan

import "context"

type semaphore chan struct{}

func (s semaphore) acquire(ctx context.Context) bool {
	select {
	case s <- struct{}{}:
	case <-ctx.Done():
		return false
	}
	if ctx.Err() != nil {
		<-s
		return false
	}
	return true
}

func (s semaphore) release() { <-s }
