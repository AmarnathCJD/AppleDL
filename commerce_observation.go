package applemusic

import "strings"

// CommerceObservation describes response contents, never media API validity.
type CommerceObservation string

const (
	CommerceUnclassified       CommerceObservation = "unclassified"
	CommerceCredentialReceived CommerceObservation = "credential-received-unverified"
)

// Observation recognizes a nonempty credential and identity in an HTTP 2xx
// response with no known error/challenge fields. It deliberately does not assign
// a success/failure meaning to plist status (including the observed -128).
// A credential can be issued before account setup or media access is complete.
func (r *CommerceResponse) Observation() CommerceObservation {
	if r == nil || r.HTTPStatus < 200 || r.HTTPStatus >= 300 {
		return CommerceUnclassified
	}
	for name, values := range r.HTTPHeaders {
		if strings.EqualFold(name, "X-Apple-AMD-Action") || strings.EqualFold(name, "Location") {
			for _, value := range values {
				if value != "" {
					return CommerceUnclassified
				}
			}
		}
	}
	for _, key := range []string{"failureType", "errorCode", "customerMessage"} {
		if _, exists := r.Fields[key]; exists {
			return CommerceUnclassified
		}
	}
	a, err := r.ExtractAccount()
	if err != nil || a.Username == "" || a.DSID == 0 || a.AltDSID == "" || !a.HasPasswordToken || a.PasswordToken == "" {
		return CommerceUnclassified
	}
	return CommerceCredentialReceived
}

func (*CommerceResponse) String() string   { return "CommerceResponse{redacted}" }
func (*CommerceResponse) GoString() string { return "CommerceResponse{redacted}" }

// Destroy drops references and clears owned byte slices/maps. Go strings and
// copies held by the caller cannot be guaranteed erased.
func (r *CommerceResponse) Destroy() {
	if r == nil {
		return
	}
	clearCommerceValue(r.Fields)
	clear(r.HTTPHeaders)
	*r = CommerceResponse{}
}

func clearCommerceValue(v any) {
	switch value := v.(type) {
	case []byte:
		clear(value)
	case map[string]any:
		for _, child := range value {
			clearCommerceValue(child)
		}
		clear(value)
	case []any:
		for _, child := range value {
			clearCommerceValue(child)
		}
		clear(value)
	}
}
