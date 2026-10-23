package applemusic

import (
	"encoding/json"
	"errors"
	"time"
)

// PET extracts t["com.apple.gs.idms.pet"]["token"] from decoded IdMS account
// data. It checks only the observed structure and a nonempty string value;
// it does not establish token validity, expiry or account-data integrity.
// The returned credential is sensitive and must not be logged.
func (r *PasswordExchangeResult) PET() (string, error) {
	invalid := errors.New("IdMS account data has no valid PET")
	if r == nil {
		return "", invalid
	}
	var tokens map[string]json.RawMessage
	if err := json.Unmarshal(r.AccountData["t"], &tokens); err != nil || tokens == nil {
		return "", invalid
	}
	var entry map[string]json.RawMessage
	if err := json.Unmarshal(tokens["com.apple.gs.idms.pet"], &entry); err != nil || entry == nil {
		return "", invalid
	}
	var token string
	if err := json.Unmarshal(entry["token"], &token); err != nil || token == "" {
		return "", invalid
	}
	return token, nil
}

// PETExpiry reads the observed Unix-millisecond expiry of the PET entry.
// A missing or invalid expiry is not evidence that a token remains valid.
func (r *SRPExchangeResult) PETExpiry() (time.Time, error) {
	invalid := errors.New("IdMS PET has no valid expiry")
	if r == nil {
		return time.Time{}, invalid
	}
	var tokens map[string]json.RawMessage
	if json.Unmarshal(r.AccountData["t"], &tokens) != nil {
		return time.Time{}, invalid
	}
	var entry struct {
		Expiry int64 `json:"expiry"`
	}
	if json.Unmarshal(tokens["com.apple.gs.idms.pet"], &entry) != nil {
		return time.Time{}, invalid
	}
	n := entry.Expiry
	if n <= 0 || n > 253402300799999 {
		return time.Time{}, invalid
	}
	return time.UnixMilli(n), nil
}
