package standalone

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"net/http"

	"github.com/AmarnathCJD/AppleDL"
)

type Config struct {
	StateDir string // absolute directory for a separate local device; encrypted with a local key
}

type StatusError struct {
	Operation string
	Code      int32
}

func (e *StatusError) Error() string {
	return fmt.Sprintf("native %s returned status %d", e.Operation, e.Code)
}

// Device owns an isolated runtime and a separate persistent device identity.
// It uses no Android process, Python, network service or emulator state.
type Device struct {
	gate   chan struct{}
	vm     *goVM
	store  *stateStore
	state  *diskState
	active *Session
	closed bool
}

func (*Device) String() string   { return "StandaloneDevice{redacted}" }
func (*Device) GoString() string { return "StandaloneDevice{redacted}" }

func Open(ctx context.Context, cfg Config) (*Device, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	s, state, err := openState(cfg.StateDir)
	if err != nil {
		return nil, err
	}
	v, err := newGoVM()
	if err != nil {
		s.close()
		return nil, err
	}
	v.files.data, v.files.dirs = state.Files, state.Dirs
	if state.Modified == nil {
		state.Modified = map[string]int64{}
	}
	v.files.modified = state.Modified
	// Migrate earlier snapshots without changing identity or native file bytes.
	for name := range state.Files {
		if v.files.modified[name] == 0 {
			v.files.touch(name)
		}
	}
	d := &Device{gate: make(chan struct{}, 1), vm: v, store: s, state: state}
	err = d.run(ctx, false, func() error {
		path, library, id := v.string("/adi"), v.string("/native"), v.string(state.AndroidID)
		defer v.free(path)
		defer v.free(library)
		defer v.free(id)
		for _, op := range []struct {
			name string
			args []uint64
		}{
			{"nf92ngaK92", []uint64{path}}, {"kq56gsgHG6", []uint64{library}},
			{"nf92ngaK92", []uint64{path}}, {"Sph98paBcz", []uint64{id, uint64(len(state.AndroidID))}},
		} {
			if err := d.invoke(ctx, op.name, op.args...); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		d.Close()
		return nil, err
	}
	return d, nil
}

func (d *Device) persist() error {
	if !d.vm.files.dirty {
		return nil
	}
	d.state.Files, d.state.Dirs = d.vm.files.data, d.vm.files.dirs
	d.state.Modified = d.vm.files.modified
	if err := d.store.save(d.state); err != nil {
		d.vm.failure = err
		return err
	}
	d.vm.files.dirty = false
	return nil
}

func (d *Device) run(ctx context.Context, withSession bool, fn func() error) (err error) {
	select {
	case d.gate <- struct{}{}:
	case <-ctx.Done():
		return ctx.Err()
	}
	defer func() { <-d.gate }()
	if d.closed {
		return errors.New("standalone device is closed")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if d.vm.failure != nil {
		return d.vm.failure
	}
	if !withSession && d.active != nil {
		return errors.New("native provisioning session is active")
	}
	defer func() {
		if recover() != nil {
			d.vm.failure = errors.New("native device operation failed")
			err = d.vm.failure
		}
		err = errors.Join(err, d.persist())
	}()
	return fn()
}

func (d *Device) invoke(ctx context.Context, name string, args ...uint64) error {
	code, err := d.vm.call(ctx, name, args...)
	if err != nil {
		return err
	}
	if code != 0 {
		return &StatusError{name, code}
	}
	return nil
}

func validDSID(dsid int64) bool {
	return dsid == applemusic.AnisetteV3DSID || dsid == applemusic.AnisetteV15DSID
}

// Status returns 0 for provisioned and -45061 for unprovisioned. Other native
// codes are preserved and must not be treated as permission to overwrite state.
func (d *Device) Status(ctx context.Context, dsid int64) (code int32, err error) {
	if !validDSID(dsid) {
		return 0, errors.New("unsupported anisette DSID")
	}
	err = d.run(ctx, false, func() error { var e error; code, e = d.vm.call(ctx, "aslgmuibau", uint64(dsid)); return e })
	return
}

// StableID is this local device's Android-ID text. It is sensitive metadata;
// callers may compose headers with it but must not log it.
func (d *Device) StableID(ctx context.Context) (id string, err error) {
	err = d.run(ctx, false, func() error { id = d.state.AndroidID; return nil })
	return
}

func (d *Device) output(ctx context.Context, slots uint64) (data []byte, err error) {
	ptr := binary.LittleEndian.Uint64(d.vm.read(slots, 8))
	size := binary.LittleEndian.Uint32(d.vm.read(slots+8, 4))
	if ptr == 0 {
		return nil, errors.New("native output is missing")
	}
	defer func() {
		err = errors.Join(err, d.invoke(context.Background(), "jk24uiwqrg", ptr))
		if err != nil {
			clear(data)
			data = nil
		}
	}()
	if size == 0 || size > bufferLimit {
		return nil, errors.New("native output size invalid")
	}
	return d.vm.read(ptr, uint64(size)), nil
}

// AnisetteHeaders returns fresh MID/OTP headers only. These are not a complete
// GrandSlam request and their generation does not establish account login.
func (d *Device) AnisetteHeaders(ctx context.Context, dsid int64) (headers http.Header, err error) {
	if !validDSID(dsid) {
		return nil, errors.New("unsupported anisette DSID")
	}
	err = d.run(ctx, false, func() error {
		v := d.vm
		out := v.alloc(32)
		defer v.free(out)
		if err := d.invoke(ctx, "qi864985u0", uint64(dsid), out, out+8, out+16, out+24); err != nil {
			return err
		}
		mid, em := d.output(ctx, out)
		defer clear(mid)
		otp, eo := d.output(ctx, out+16)
		defer clear(otp)
		if err := errors.Join(em, eo); err != nil {
			return err
		}
		m, o := "X-Apple-I-MD-M", "X-Apple-I-MD"
		if dsid == applemusic.AnisetteV15DSID {
			m, o = "X-Apple-AMD-M", "X-Apple-AMD"
		}
		headers = http.Header{}
		headers.Set(m, base64.StdEncoding.EncodeToString(mid))
		headers.Set(o, base64.StdEncoding.EncodeToString(otp))
		return nil
	})
	if err != nil {
		return nil, err
	}
	return headers, nil
}

// Start implements applemusic.NativeProvisioningStarter. It only accepts an
// unprovisioned local identity, and never erases or replaces existing ADI state.
func (d *Device) Start(ctx context.Context, dsid int64, spim []byte) (cpim []byte, session applemusic.NativeProvisioningSession, err error) {
	if !validDSID(dsid) || len(spim) == 0 || len(spim) > bufferLimit {
		return nil, nil, errors.New("invalid provisioning input")
	}
	err = d.run(ctx, false, func() error {
		v := d.vm
		status, err := v.call(ctx, "aslgmuibau", uint64(dsid))
		if err != nil {
			return err
		}
		if status != -45061 {
			return &StatusError{"start refused", status}
		}
		input, out := v.data(spim), v.alloc(32)
		defer v.free(input)
		defer v.free(out)
		if err := d.invoke(ctx, "rsegvyrt87", uint64(dsid), input, uint64(len(spim)), out, out+8, out+16); err != nil {
			return err
		}
		s := &Session{device: d, id: binary.LittleEndian.Uint32(v.read(out+16, 4))}
		d.active, session = s, s
		cpim, err = d.output(ctx, out)
		return err
	})
	if err != nil {
		clear(cpim)
		cpim = nil
	}
	return
}

type Session struct {
	device            *Device
	id                uint32
	attempted, closed bool
}

var _ applemusic.NativeProvisioningSession = (*Session)(nil)

func (*Session) String() string   { return "NativeSession{redacted}" }
func (*Session) GoString() string { return "NativeSession{redacted}" }

func (s *Session) Finish(ctx context.Context, ptm, tk []byte) error {
	if len(ptm) == 0 || len(tk) == 0 || len(ptm) > bufferLimit || len(tk) > bufferLimit {
		return errors.New("invalid native finish input")
	}
	d := s.device
	return d.run(ctx, true, func() error {
		if s.closed || s.attempted || d.active != s {
			return errors.New("native session unavailable")
		}
		s.attempted = true
		p, t := d.vm.data(ptm), d.vm.data(tk)
		defer d.vm.free(p)
		defer d.vm.free(t)
		return d.invoke(ctx, "uv5t6nhkui", uint64(s.id), p, uint64(len(ptm)), t, uint64(len(tk)))
	})
}

func (s *Session) closeLocked() error {
	if s.closed {
		return nil
	}
	s.closed = true
	d := s.device
	d.active = nil
	return d.invoke(context.Background(), "fy34trz2st", uint64(s.id))
}

func (s *Session) Close() error {
	d := s.device
	return d.run(context.Background(), true, s.closeLocked)
}

// Close saves changes and releases all local VM memory. It does not erase state.
func (d *Device) Close() (err error) {
	d.gate <- struct{}{}
	defer func() { <-d.gate }()
	if d.closed {
		return nil
	}
	d.closed = true
	defer d.store.close()
	defer d.vm.close()
	defer func() {
		for _, data := range d.vm.files.data {
			clear(data)
		}
		d.state.AndroidID = ""
	}()
	if d.active != nil {
		err = d.active.closeLocked()
	}
	if d.vm.failure == nil {
		err = errors.Join(err, d.invoke(context.Background(), "madsvsfvjk"))
	}
	return errors.Join(err, d.persist())
}
