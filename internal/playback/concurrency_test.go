package playback

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"
)

func TestRunParallelOverlapAndKeepOrdinals(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	arrivals := make(chan int, 2)
	release := make(chan struct{})
	done := make(chan error, 1)
	var active, maximum atomic.Int32
	seen := make([]int, 7)
	go func() {
		done <- runParallel(ctx, len(seen), 2, func(ctx context.Context, i int) error {
			n := active.Add(1)
			defer active.Add(-1)
			for prev := maximum.Load(); n > prev; prev = maximum.Load() {
				if maximum.CompareAndSwap(prev, n) {
					break
				}
			}
			if i < 2 {
				arrivals <- i
				select {
				case <-release:
				case <-ctx.Done():
					return ctx.Err()
				}
			}
			seen[i]++
			return nil
		})
	}()
	for range 2 {
		select {
		case <-arrivals:
		case <-ctx.Done():
			t.Fatal("license computations did not overlap")
		}
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if maximum.Load() != 2 || active.Load() != 0 {
		t.Fatal("incorrect concurrency bound or unjoined worker")
	}
	for i, n := range seen {
		if n != 1 {
			t.Fatalf("key %d executed %d times", i, n)
		}
	}
}

func TestRunParallelFailureCancelsAndJoins(t *testing.T) {
	errLicense := errors.New("test license rejection")
	started := make(chan struct{})
	var joined atomic.Bool
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	err := runParallel(ctx, 16, 2, func(ctx context.Context, i int) error {
		switch i {
		case 0:
			select {
			case <-started:
				return errLicense
			case <-ctx.Done():
				return ctx.Err()
			}
		case 1:
			close(started)
			<-ctx.Done()
			joined.Store(true)
			return ctx.Err()
		default:
			t.Error("queued key started after failure")
			return nil
		}
	})
	if !errors.Is(err, errLicense) || !joined.Load() {
		t.Fatal("lost originating failure or worker was not joined")
	}
}

func TestRunParallelCanceledBeforeStart(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	err := runParallel(ctx, 16, 2, func(context.Context, int) error { t.Error("work started after cancellation"); return nil })
	if !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}
