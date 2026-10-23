package applemusic

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"net/http"
)

// GrandSlamOptions supplies the per-request device data. Headers must come from
// the caller's matching device/Anisette environment; this package does not
// provision it. Supply fresh data for each step. The native password path uses
// CKAuth=false, CKGen=true; the continuation-key path reverses those flags.
type GrandSlamOptions struct {
	Locale  string
	CKAuth  bool
	CKGen   bool
	Headers http.Header
}

func (o GrandSlamOptions) cpd() map[string]any {
	return map[string]any{"bootstrap": true, "ckauth": o.CKAuth, "ckgen": o.CKGen, "loc": o.Locale}
}

// GrandSlamResponseError preserves a well-formed server Response that cannot be
// used for the requested SRP step. Inspect Response and HTTPHeaders explicitly;
// both can contain sensitive continuation data. Error redacts them.
// Wire status codes and two-factor continuation are not interpreted yet.
type GrandSlamResponseError struct {
	Response    map[string]json.RawMessage
	HTTPHeaders http.Header
}

func (*GrandSlamResponseError) Error() string {
	return "GrandSlam response does not contain a usable SRP result"
}

type SRPInitResponse struct {
	Challenge     SRPChallenge
	Continuation  string // c is opaque text, not decoded Base64
	TransactionID string // ptxid
	Response      map[string]json.RawMessage
	HTTPHeaders   http.Header
}

// SRPCompleteResponse contains unverified server data. Verify M2 using the same
// SRPSession before using its key. The examined native success branch checks M2
// then decodes SPD; no NP check was observed there. NP's role remains unresolved.
// This transport does not establish a commerce account/session.
type SRPCompleteResponse struct {
	ServerProof []byte // M2
	NP          []byte // np; meaning and verification remain under investigation
	SPD         []byte // encrypted spd
	Response    map[string]json.RawMessage
	HTTPHeaders http.Header
}

// InitSRP sends the native JSON init envelope. publicKey is the padded A2k from
// SRPSession.PublicKey. This operation neither sends a password nor logs in.
func (c *Client) InitSRP(ctx context.Context, username string, publicKey []byte, options GrandSlamOptions) (*SRPInitResponse, error) {
	if username == "" || options.Locale == "" || len(publicKey) != 256 {
		return nil, errors.New("SRP init requires username, locale and a 256-byte public key")
	}
	a := new(big.Int).SetBytes(publicKey)
	if a.Sign() == 0 || a.Cmp(srpN) >= 0 {
		return nil, errors.New("invalid SRP client public key")
	}
	response, headers, err := c.grandSlam(ctx, map[string]any{
		"cpd": options.cpd(), "u": username, "A2k": publicKey,
		"o": "init", "ps": []string{"s2k", "s2k_fo"},
	}, options.Headers)
	if err != nil {
		return nil, err
	}
	salt, okS := binaryField(response, "s")
	serverPublic, okB := binaryField(response, "B")
	scheme, okSP := stringField(response, "sp")
	continuation, okC := stringField(response, "c")
	transaction, okT := stringField(response, "ptxid")
	var iterations uint64
	okI := len(response["i"]) > 0 && string(response["i"]) != "null" && json.Unmarshal(response["i"], &iterations) == nil
	if !okS || !okB || !okSP || !okC || !okT || !okI ||
		len(salt) == 0 || len(salt) > 1024 || len(serverPublic) == 0 || len(serverPublic) > 256 ||
		(scheme != string(S2K) && scheme != string(S2KFO)) || iterations == 0 || iterations > MaxPasswordIterations || continuation == "" {
		return nil, &GrandSlamResponseError{Response: response, HTTPHeaders: headers}
	}
	return &SRPInitResponse{
		Challenge:    SRPChallenge{Salt: salt, ServerPublic: serverPublic, Scheme: PasswordScheme(scheme), Iterations: int(iterations)},
		Continuation: continuation, TransactionID: transaction, Response: response, HTTPHeaders: headers,
	}, nil
}

// CompleteSRP sends M1 and the unchanged continuation returned by InitSRP. The
// caller owns the SRPSession and must verify the returned M2. This operation
// does not imply that device verification or Apple account login succeeded.
func (c *Client) CompleteSRP(ctx context.Context, username, continuation string, proof []byte, options GrandSlamOptions) (*SRPCompleteResponse, error) {
	if username == "" || continuation == "" || options.Locale == "" || len(proof) == 0 || len(proof) > 32 {
		return nil, errors.New("SRP complete requires username, continuation, locale and a valid proof length")
	}
	response, headers, err := c.grandSlam(ctx, map[string]any{
		"cpd": options.cpd(), "u": username, "M1": proof, "o": "complete", "c": continuation,
	}, options.Headers)
	if err != nil {
		return nil, err
	}
	m2, okM := binaryField(response, "M2")
	np, okN := binaryField(response, "np")
	spd, okS := binaryField(response, "spd")
	if !okM || !okN || !okS || len(m2) == 0 || len(m2) > 32 || len(spd) == 0 || len(spd)%16 != 0 {
		return nil, &GrandSlamResponseError{Response: response, HTTPHeaders: headers}
	}
	return &SRPCompleteResponse{ServerProof: m2, NP: np, SPD: spd, Response: response, HTTPHeaders: headers}, nil
}

func (c *Client) grandSlam(ctx context.Context, request map[string]any, headers http.Header) (map[string]json.RawMessage, http.Header, error) {
	var envelope struct {
		Response map[string]json.RawMessage `json:"Response"`
	}
	h, err := c.postJSON(ctx, map[string]any{"Header": map[string]string{"v": "1"}, "Request": request}, headers, &envelope)
	if err != nil {
		return nil, h, err
	}
	if envelope.Response == nil {
		return nil, h, errors.New("missing GrandSlam Response object")
	}
	return envelope.Response, h, nil
}

func stringField(fields map[string]json.RawMessage, name string) (string, bool) {
	raw := fields[name]
	var value string
	if len(raw) == 0 || raw[0] != '"' || json.Unmarshal(raw, &value) != nil {
		return "", false
	}
	return value, true
}

func binaryField(fields map[string]json.RawMessage, name string) ([]byte, bool) {
	value, ok := stringField(fields, name)
	if !ok {
		return nil, false
	}
	decoded, err := base64.StdEncoding.DecodeString(value)
	return decoded, err == nil
}
