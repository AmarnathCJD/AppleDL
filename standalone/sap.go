package standalone

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"time"

	"github.com/AmarnathCJD/AppleDL"
	"howett.net/plist"
)

// SAPSigner owns a separate, serialized native signing session. Its identity
// must be the same StableID used by the local Device. No Android state is read.
// Setup is ephemeral; Close releases the session and all native memory.
type SAPSigner struct {
	identity                 string
	gate                     chan struct{}
	vm                       *goVM
	hw, session              uint64
	ready, attempted, closed bool
}

func (*SAPSigner) String() string   { return "SAPSigner{redacted}" }
func (*SAPSigner) GoString() string { return "SAPSigner{redacted}" }

func NewSAPSigner(ctx context.Context, cfg Config, androidID string) (s *SAPSigner, err error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	id, e := hex.DecodeString(androidID)
	if e != nil || len(id) != 8 {
		return nil, errors.New("SAP requires the local Android-ID text")
	}
	v, err := newGoVM()
	if err != nil {
		return nil, err
	}
	s = &SAPSigner{gate: make(chan struct{}, 1), vm: v, identity: androidID}
	defer func() {
		if recover() != nil {
			err = errors.New("initialize SAP runtime failed")
		}
		if err != nil {
			s.Close()
			s = nil
		}
	}()
	v.instructionLimit = 200_000_000
	first := len(v.constructors)
	if err = v.loadGoImage("libCoreFP.so", 0x30000000); err != nil {
		return s, err
	}
	for _, address := range v.constructors[first:] {
		if _, err = v.callAddress(ctx, address); err != nil {
			return s, err
		}
	}
	path, text := v.string("/native"), v.string(androidID)
	defer v.free(path)
	defer v.free(text)
	s.hw = v.alloc(24) // FairPlayHWInfo: uint32 length followed by 20 bytes.
	slot := v.alloc(8)
	defer v.free(slot)
	for _, op := range []struct {
		name string
		args []uint64
	}{
		{"N8jdR29h", []uint64{path}},
		{"bsawCXd", []uint64{text, uint64(len(androidID))}},
		{"FKgu8fbnvGFG", []uint64{s.hw}},
		{"cp2g1b9ro", []uint64{slot, s.hw}},
	} {
		if err = s.invoke(ctx, op.name, op.args...); err != nil {
			return s, err
		}
	}
	s.session = binary.LittleEndian.Uint64(v.read(slot, 8))
	if s.session == 0 {
		return s, errors.New("SAP session missing")
	}
	return s, nil
}

func (s *SAPSigner) invoke(ctx context.Context, name string, args ...uint64) error {
	code, err := s.vm.call(ctx, name, args...)
	if err != nil {
		return err
	}
	if code != 0 {
		return &StatusError{Operation: name, Code: code}
	}
	return nil
}

func (s *SAPSigner) run(ctx context.Context, fn func() error) (err error) {
	select {
	case s.gate <- struct{}{}:
	case <-ctx.Done():
		return ctx.Err()
	}
	defer func() { <-s.gate }()
	if s.closed {
		return errors.New("SAP signer is closed")
	}
	if err = ctx.Err(); err != nil {
		return err
	}
	if s.vm.failure != nil {
		return s.vm.failure
	}
	defer func() {
		if recover() != nil {
			s.vm.failure = errors.New("SAP operation failed")
			err = s.vm.failure
		}
	}()
	return fn()
}

// output copies a native buffer and always disposes its native allocation.
func (s *SAPSigner) output(slot uint64) (data []byte, err error) {
	ptr := binary.LittleEndian.Uint64(s.vm.read(slot, 8))
	n := binary.LittleEndian.Uint32(s.vm.read(slot+8, 4))
	if ptr == 0 {
		if n != 0 {
			return nil, errors.New("SAP output pointer missing")
		}
		return nil, nil
	}
	defer func() {
		err = errors.Join(err, s.invoke(context.Background(), "jEHf8Xzsv8K", ptr))
		if err != nil {
			clear(data)
			data = nil
		}
	}()
	if n > bufferLimit {
		return nil, errors.New("SAP output exceeds bounds")
	}
	return s.vm.read(ptr, uint64(n)), nil
}

func (s *SAPSigner) exchange(ctx context.Context, input []byte) (output []byte, state int8, err error) {
	if len(input) == 0 || len(input) > bufferLimit {
		return nil, 0, errors.New("invalid SAP exchange input")
	}
	v := s.vm
	in, out := v.data(input), v.alloc(24)
	defer v.free(in)
	defer v.free(out)
	callErr := s.invoke(ctx, "Mib5yocT", 200, s.hw, s.session, in, uint64(len(input)), out, out+8, out+16)
	output, err = s.output(out)
	err = errors.Join(callErr, err)
	state = int8(v.read(out+16, 1)[0])
	if err != nil {
		clear(output)
		output = nil
	}
	return
}

// Setup accepts the observed version-200 endpoints from Apple's current bag.
// It makes one certificate request and one setup POST, with no redirects or
// automatic retries. A failed setup requires closing and creating a new signer.
func (s *SAPSigner) Setup(ctx context.Context, client *http.Client, certURL, setupURL, userAgent string) error {
	if certURL != "https://s.mzstatic.com/sap/setupCert.plist" || setupURL != "https://fpinit.itunes.apple.com/v1/signSapSetup" {
		return errors.New("unsupported SAP setup endpoints")
	}
	hc := http.Client{Timeout: 30 * time.Second}
	if client != nil {
		hc = *client
	}
	hc.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return s.run(ctx, func() error {
		if s.attempted {
			return errors.New("SAP setup already attempted")
		}
		s.attempted = true
		request := func(method, url, key string, body []byte) ([]byte, error) {
			req, err := http.NewRequestWithContext(ctx, method, url, bytes.NewReader(body))
			if err != nil {
				return nil, errors.New("create SAP request failed")
			}
			req.GetBody = nil
			req.Header.Set("User-Agent", userAgent)
			if body != nil {
				req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			}
			response, err := hc.Do(req)
			if err != nil {
				return nil, errors.New("SAP network request failed")
			}
			defer response.Body.Close()
			if response.StatusCode != 200 {
				return nil, &applemusic.HTTPError{StatusCode: response.StatusCode}
			}
			raw, err := io.ReadAll(io.LimitReader(response.Body, bufferLimit+1))
			defer clear(raw)
			if err != nil || len(raw) > bufferLimit {
				return nil, errors.New("invalid SAP response size")
			}
			var fields map[string]any
			if _, err = plist.Unmarshal(raw, &fields); err != nil {
				return nil, errors.New("invalid SAP response plist")
			}
			data, ok := fields[key].([]byte)
			if !ok || len(data) == 0 {
				return nil, errors.New("SAP response data missing")
			}
			return data, nil
		}
		cert, err := request("GET", certURL, "sign-sap-setup-cert", nil)
		if err != nil {
			return err
		}
		defer clear(cert)
		out, state, err := s.exchange(ctx, cert)
		if err != nil {
			return err
		}
		defer clear(out)
		if state != 1 || len(out) == 0 {
			return errors.New("SAP did not enter negotiating state")
		}
		body, err := plist.Marshal(map[string]any{"sign-sap-setup-buffer": out}, plist.XMLFormat)
		if err != nil {
			return errors.New("encode SAP setup failed")
		}
		defer clear(body)
		response, err := request("POST", setupURL, "sign-sap-setup-buffer", body)
		if err != nil {
			return err
		}
		defer clear(response)
		out, state, err = s.exchange(ctx, response)
		defer clear(out)
		if err != nil {
			return err
		}
		if state != 0 {
			return errors.New("SAP negotiation incomplete")
		}
		s.ready = true
		return nil
	})
}

// Sign signs exactly body, with no reserialization or compression.
func (s *SAPSigner) Sign(ctx context.Context, body []byte) (signature []byte, err error) {
	if len(body) == 0 || len(body) > bufferLimit {
		return nil, errors.New("invalid SAP signing input")
	}
	err = s.run(ctx, func() error {
		if !s.ready {
			return errors.New("SAP setup required")
		}
		in, out := s.vm.data(body), s.vm.alloc(16)
		defer s.vm.free(in)
		defer s.vm.free(out)
		callErr := s.invoke(ctx, "Fc3vhtJDvr", s.session, in, uint64(len(body)), out, out+8)
		var e error
		signature, e = s.output(out)
		if e = errors.Join(callErr, e); e != nil {
			return e
		}
		if len(signature) == 0 {
			return errors.New("SAP signature missing")
		}
		return nil
	})
	if err != nil {
		clear(signature)
		signature = nil
	}
	return
}

func (s *SAPSigner) Close() (err error) {
	s.gate <- struct{}{}
	defer func() { <-s.gate }()
	if s.closed {
		return nil
	}
	s.closed = true
	defer s.vm.close()
	defer func() {
		if recover() != nil {
			err = errors.New("close SAP session failed")
		}
	}()
	if s.session != 0 && s.vm.failure == nil {
		err = s.invoke(context.Background(), "IPaI1oem5iL", s.session)
	}
	s.session = 0
	return
}
