package applemusic

import (
	"context"
	"errors"
	"net/http"

	"howett.net/plist"
)

const commerceContentType = "application/x-apple-plist"

// PETCredentials describes the native CommerceAuthenticateTask request.
// AppleID is the username of the corresponding local account identity.
// GUID is optional on the wire; when supplied it must match the device provider.
type PETCredentials struct {
	AppleID string
	PET     string
	GUID    string
}

// CommerceRequest is an isolated snapshot for request preparation. Body contains
// the exact serialized bytes that will be sent; changing this snapshot cannot
// change the destination, method or body. Headers contains application headers;
// net/http may also add transport headers and cookies from the HTTP client's Jar.
// All fields may contain credentials or device data. Do not log the snapshot.
type CommerceRequest struct {
	Method  string
	URL     string
	Headers http.Header
	Body    []byte
}

// CommerceRequestPreparer supplies the complete application header map for this
// request. It must preserve Content-Type and handle fresh matching device data,
// FairPlay identity and bag-dependent Mescal signing as required by the native
// flow. Body is already serialized and must be signed as given, without encoding
// it again. No particular signature header is mandatory for every bag rule.
// Return an error if preparation cannot be completed; no request will be sent.
// A no-op callback is appropriate only when the caller has established that the
// existing headers meet the endpoint's requirements. This library cannot check
// that device data or signatures are valid. Calls are synchronous, once per
// AuthenticatePET invocation, with no automatic challenge or redirect handling.
type CommerceRequestPreparer func(context.Context, CommerceRequest) (http.Header, error)

type CommerceOptions struct {
	Headers                 http.Header
	IgnoreAccountConversion bool
	PrepareRequest          CommerceRequestPreparer
}

// CommerceResponse preserves the plist dictionary without classifying an HTTP
// success as a successful login. Fields can include accountInfo, passwordToken,
// failureType and server challenges, and must be interpreted by the account
// flow. Fields and HTTPHeaders can contain sensitive account data and cookies.
type CommerceResponse struct {
	Fields      map[string]any
	HTTPHeaders http.Header
	HTTPStatus  int
}

// CommercePreparationError redacts provider diagnostics. Its unwrapped cause
// may contain secrets; inspect it only explicitly when needed.
type CommercePreparationError struct{ Err error }

func (e *CommercePreparationError) Error() string { return "commerce request preparation failed" }
func (e *CommercePreparationError) Unwrap() error { return e.Err }

// AuthenticatePET posts one modern commerce authentication request to the
// trusted authenticateAccount URL resolved by the caller from Apple's bag.
// This is a protocol component, not a completed Apple Music sign-in. The caller
// must interpret challenges and install the resulting local media account.
func (c *Client) AuthenticatePET(ctx context.Context, endpoint string, credentials PETCredentials, options CommerceOptions) (*CommerceResponse, error) {
	if credentials.AppleID == "" || credentials.PET == "" || options.PrepareRequest == nil {
		return nil, errors.New("commerce authentication requires Apple ID, PET and a request preparer")
	}
	if err := validateEndpoint(endpoint); err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	body := map[string]any{
		"appleId": credentials.AppleID, "password": credentials.PET,
		"createSession": true, "rmp": int64(0),
	}
	if credentials.GUID != "" {
		body["guid"] = credentials.GUID
	}
	data, err := plist.Marshal(body, plist.XMLFormat)
	if err != nil {
		return nil, errors.New("encode commerce authentication plist failed")
	}
	req, err := c.newPostRequest(ctx, endpoint, data, commerceContentType, options.Headers)
	if err != nil {
		return nil, err
	}
	if options.IgnoreAccountConversion {
		req.Header.Set("X-Apple-Ignore-Account-Conversion", "true")
	}
	headers, err := options.PrepareRequest(ctx, CommerceRequest{
		Method: req.Method, URL: req.URL.String(), Headers: req.Header.Clone(),
		Body: append([]byte(nil), data...),
	})
	if err != nil {
		return nil, &CommercePreparationError{Err: err}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	// Normalize and copy the returned map. Do not overwrite signed headers after
	// preparation or let a callback's retained snapshot alter the request body.
	req.Header = make(http.Header, len(headers))
	for key, values := range headers {
		canonical := http.CanonicalHeaderKey(key)
		if _, exists := req.Header[canonical]; exists {
			return nil, errors.New("commerce preparation returned duplicate header names")
		}
		req.Header[canonical] = append([]string(nil), values...)
	}
	if values := req.Header.Values("Content-Type"); len(values) != 1 || values[0] != commerceContentType {
		return nil, errors.New("commerce preparation must preserve the plist content type")
	}
	// This API sends the original body, without compression or framing changes.
	for _, name := range []string{"Content-Encoding", "Content-Length", "Transfer-Encoding", "Trailer", "Host"} {
		if _, exists := req.Header[name]; exists {
			return nil, errors.New("commerce preparation returned an unsupported transport header")
		}
	}
	// Signed credentials are not replayable. net/http uses GetBody together with
	// idempotency headers to decide whether to retry a POST on a reused connection.
	req.GetBody = nil
	responseData, responseHeaders, status, err := c.sendWithStatus(req)
	defer clear(responseData)
	response := &CommerceResponse{HTTPHeaders: responseHeaders, HTTPStatus: status}
	if err != nil {
		if responseHeaders == nil {
			return nil, err
		}
		return response, err
	}
	var fields map[string]any
	if _, err := plist.Unmarshal(responseData, &fields); err != nil || fields == nil {
		return response, errors.New("invalid commerce authentication plist dictionary")
	}
	return &CommerceResponse{Fields: fields, HTTPHeaders: responseHeaders, HTTPStatus: status}, nil
}
