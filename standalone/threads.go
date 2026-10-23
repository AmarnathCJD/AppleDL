package standalone

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"time"
)

// Guest threads share one Go virtual address space and run in bounded slices.
// Each owns a full CPU context (including SIMD registers), stack and TLS.
// Sleeping workers are serviced before the next API call and during long calls;
// the owner never reenters execution from an import callback.
type guestThread struct {
	id                 uint64
	cpu                uint64
	finished           bool
	wake               time.Time
	lockWait, onceWait uint64
	writeWait          bool
	resumePC           uint64
}

type guestRWLock struct {
	writer  uint64
	readers map[uint64]int
}

func (v *goVM) initThreads() {
	v.rwlocks = make(map[uint64]*guestRWLock)
	v.onceOwners = make(map[uint64]uint64)
	t := &guestThread{id: 1, cpu: uint64(len(v.threads) + 1)}
	v.threads = []*guestThread{t}
	v.currentThread = t
	v.saveCPU(t.cpu)
}

// Route yields through the execution end address and restore the saved resume
// address before the next slice.
func (v *goVM) suspendThread() {
	v.currentThread.resumePC = v.reg(regPC)
	v.setReg(regPC, arenaBase)
	v.stopExecution()
}

func (v *goVM) createThread(a [8]uint64) (uint64, error) {
	if a[1] != 0 {
		return 0, errors.New("native thread attributes unsupported")
	}
	if len(v.threads) >= 8 {
		return 11, nil
	} // EAGAIN; no thread was created.
	if a[0] == 0 || a[2] == 0 {
		return 22, nil
	}
	v.saveCPU(v.currentThread.cpu)
	id := uint64(len(v.threads) + 1)
	base := uint64(0x80000000) + id*0x200000
	v.mapMemory(base, 0x100000)
	t := &guestThread{id: id, cpu: uint64(len(v.threads) + 1)}
	v.threads = append(v.threads, t)
	v.setReg(regPC, a[2])
	v.setReg(regSP, base+0xff000)
	v.setReg(regTLS, base+0x1000)
	v.setReg(regLR, arenaBase)
	v.setReg(regX0, a[3])
	v.saveCPU(t.cpu)
	v.restoreCPU(v.currentThread.cpu)
	v.write(a[0], binary.LittleEndian.AppendUint64(nil, id))
	v.yieldThread = true
	return 0, nil
}

func (v *goVM) rwlock(name string, a [8]uint64) (uint64, error) {
	id, addr := v.currentThread.id, a[0]
	if addr == 0 {
		return 22, nil
	}
	l := v.rwlocks[addr]
	if l == nil {
		l = &guestRWLock{readers: make(map[uint64]int)}
		v.rwlocks[addr] = l
	}
	switch name {
	case "pthread_rwlock_init", "pthread_rwlock_destroy":
		if l.writer != 0 || len(l.readers) != 0 {
			return 16, nil
		}
		if name == "pthread_rwlock_init" && a[1] != 0 {
			return 0, errors.New("native rwlock attributes unsupported")
		}
		delete(v.rwlocks, addr)
		return 0, nil
	case "pthread_rwlock_unlock":
		if l.writer == id {
			l.writer = 0
			return 0, nil
		}
		if l.readers[id] > 0 {
			l.readers[id]--
			if l.readers[id] == 0 {
				delete(l.readers, id)
			}
			return 0, nil
		}
		return 1, nil // EPERM
	case "pthread_rwlock_rdlock", "pthread_rwlock_wrlock":
		write := name == "pthread_rwlock_wrlock"
		if l.writer == id || (write && l.readers[id] > 0) {
			return 35, nil
		} // EDEADLK
		if l.writer == 0 && (!write || len(l.readers) == 0) {
			if write {
				l.writer = id
			} else {
				l.readers[id]++
			}
			return 0, nil
		}
		v.currentThread.lockWait, v.currentThread.writeWait = addr, write
		v.yieldThread = true
		return 0, nil // Retry the same import after its owner releases the lock.
	}
	return 0, errors.New("unsupported native lock")
}

func (v *goVM) threadReady(t *guestThread, now time.Time) bool {
	if t.finished || now.Before(t.wake) {
		return false
	}
	if t.onceWait != 0 && binary.LittleEndian.Uint32(v.read(t.onceWait, 4)) != 2 {
		return false
	}
	if t.lockWait != 0 {
		l := v.rwlocks[t.lockWait]
		if l != nil && (l.writer != 0 || (t.writeWait && len(l.readers) != 0)) {
			return false
		}
	}
	return true
}

func (v *goVM) runThreads(ctx context.Context) error {
	main := v.threads[0]
	main.finished = false
	v.saveCPU(main.cpu)
	deadline := time.Now().Add(5 * time.Minute)
	remaining := v.instructionLimit
	next := 0
	if len(v.threads) > 1 {
		next = 1
	}
	for {
		if err := ctx.Err(); err != nil {
			v.failure = fmt.Errorf("Go runtime cancelled; close runtime: %w", err)
			return v.failure
		}
		if remaining == 0 || time.Now().After(deadline) {
			v.failure = fmt.Errorf("native execution limit reached (budgetExhausted=%t)", remaining == 0)
			return v.failure
		}
		chosen := -1
		now := time.Now()
		for i := 0; i < len(v.threads); i++ {
			index := (next + i) % len(v.threads)
			if v.threadReady(v.threads[index], now) {
				chosen = index
				break
			}
		}
		if chosen < 0 {
			if main.finished {
				break
			}
			var wake time.Time
			for _, t := range v.threads {
				if !t.finished && t.wake.After(now) && (wake.IsZero() || t.wake.Before(wake)) {
					wake = t.wake
				}
			}
			if wake.IsZero() {
				v.failure = errors.New("native thread deadlock")
				return v.failure
			}
			timer := time.NewTimer(min(time.Until(wake), 10*time.Millisecond))
			select {
			case <-ctx.Done():
				timer.Stop()
			case <-timer.C:
			}
			continue
		}
		t := v.threads[chosen]
		v.currentThread = t
		t.lockWait, t.onceWait = 0, 0
		v.restoreCPU(t.cpu)
		budget := min(remaining, uint64(1_000_000))
		remaining -= budget // A conservative total bound, including early yields.
		if err := v.goMachine.Run(arenaBase, budget); err != nil {
			v.failure = err
		}
		if v.failure != nil {
			return v.failure
		}
		if t.resumePC != 0 {
			v.setReg(regPC, t.resumePC)
			t.resumePC = 0
		} else if v.reg(regPC) == arenaBase {
			t.finished = true
		}
		v.saveCPU(t.cpu)
		next = (chosen + 1) % len(v.threads)
		if main.finished {
			// Drain ready workers to their next sleep/return before releasing the
			// owner. A worker that spins is still bounded by the shared limits.
			ready := false
			for _, child := range v.threads[1:] {
				ready = ready || v.threadReady(child, time.Now())
			}
			if !ready {
				break
			}
		}
	}
	v.currentThread = main
	v.restoreCPU(main.cpu)
	return nil
}
