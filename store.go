package applemusic

import (
	"context"
	"errors"
	"net/http"
	"strconv"
)

// StoreCredentials describes the request in decompiled/sources/Gb/b.java.
// That Java helper's role in current first-time sign-in is unconfirmed.
// This primitive does not implement the AMS GrandSlam or two-factor flow.
type StoreCredentials struct {
	AppleID  string
	Password string
	GUID     string
	Attempt  int
}

// StoreResponse preserves named response fields without logging them. A
// successful HTTP response is not proof that authentication succeeded.
type StoreResponse struct {
	FailureType     string         `plist:"failureType"`
	ErrorCode       int64          `plist:"errorCode"`
	CustomerMessage string         `plist:"customerMessage"`
	DSID            string         `plist:"dsPersonId"`
	AltDSID         string         `plist:"altDsid"`
	PasswordToken   string         `plist:"passwordToken"`
	ClearToken      string         `plist:"clearToken"`
	AccountInfo     map[string]any `plist:"accountInfo"`
	HTTPHeaders     http.Header    `plist:"-"`
}

// AuthenticateStore calls an explicit authenticateAccount URL resolved from
// Apple's bag. It performs one attempt, leaving redirects and challenges visible.
func (c *Client) AuthenticateStore(ctx context.Context, endpoint string, credentials StoreCredentials) (*StoreResponse, error) {
	if credentials.AppleID == "" || credentials.Password == "" || credentials.GUID == "" || credentials.Attempt < 0 {
		return nil, errors.New("Apple ID, credential, GUID and nonnegative attempt are required")
	}
	body := map[string]string{
		"appleId": credentials.AppleID, "password": credentials.Password,
		"guid": credentials.GUID, "attempt": strconv.Itoa(credentials.Attempt),
		"rmp": "0", "createSession": "true", "why": "signIn",
	}
	var result StoreResponse
	headers, err := c.postPlist(ctx, endpoint, body, nil, &result)
	if err != nil {
		return nil, err
	}
	result.HTTPHeaders = headers
	return &result, nil
}
