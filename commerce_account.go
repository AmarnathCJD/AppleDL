package applemusic

import "strconv"

// CommerceAccount contains identity fields extracted from a commerce response.
// Parsing does not establish authentication success, subscription entitlement,
// token validity or completion of a challenge. Empty native string fields and a
// zero DSID are preserved; apply account-flow requirements before using them.
// Fields and JSON serialization contain sensitive data. Formatting is redacted.
type CommerceAccount struct {
	Username         string
	DSID             uint64
	AltDSID          string
	PasswordToken    string
	HasPasswordToken bool
}

func (CommerceAccount) String() string   { return "CommerceAccount{redacted}" }
func (CommerceAccount) GoString() string { return "CommerceAccount{redacted}" }

// CommerceAccountError identifies a missing or invalid structural field. It
// never contains the response value and does not classify a server challenge.
type CommerceAccountError struct{ Field string }

func (*CommerceAccountError) Error() string {
	return "commerce response has missing or invalid account fields"
}

// ExtractAccount parses the native commerce identity fields without installing
// an account, consuming the response or interpreting status/failureType. Callers
// must separately resolve challenges and verify a usable media session. The
// original Fields and HTTPHeaders remain available for that account flow.
//
// Username falls back from accountInfo.appleId to accountInfo.accountName to
// personInfo.acAccountName when a value is absent or has the wrong type, not
// when a string is empty. accountInfo must still be a dictionary. dsPersonId
// must be a decimal uint64 string; altDsid must be a string. passwordToken is
// optional: missing or non-string values produce HasPasswordToken=false.
func (r *CommerceResponse) ExtractAccount() (*CommerceAccount, error) {
	if r == nil {
		return nil, &CommerceAccountError{Field: "response"}
	}
	info, infoOK := r.Fields["accountInfo"].(map[string]any)
	username, usernameOK := info["appleId"].(string)
	if !usernameOK {
		username, usernameOK = info["accountName"].(string)
	}
	if !usernameOK {
		person, _ := r.Fields["personInfo"].(map[string]any)
		username, usernameOK = person["acAccountName"].(string)
	}
	if !usernameOK {
		return nil, &CommerceAccountError{Field: "username"}
	}
	if !infoOK {
		return nil, &CommerceAccountError{Field: "accountInfo"}
	}
	dsidText, dsidOK := r.Fields["dsPersonId"].(string)
	if !dsidOK {
		return nil, &CommerceAccountError{Field: "dsPersonId"}
	}
	// ParseUint with explicit base 10 rejects signs, whitespace, prefixes and
	// separators and checks overflow, matching the APK's unsigned from_chars.
	dsid, err := strconv.ParseUint(dsidText, 10, 64)
	if err != nil {
		return nil, &CommerceAccountError{Field: "dsPersonId"}
	}
	altDSID, altOK := r.Fields["altDsid"].(string)
	if !altOK {
		return nil, &CommerceAccountError{Field: "altDsid"}
	}
	token, tokenOK := r.Fields["passwordToken"].(string)
	return &CommerceAccount{
		Username: username, DSID: dsid, AltDSID: altDSID,
		PasswordToken: token, HasPasswordToken: tokenOK,
	}, nil
}
