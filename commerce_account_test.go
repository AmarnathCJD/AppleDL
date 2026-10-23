package applemusic

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"testing"

	"howett.net/plist"
)

func commerceAccountFields() map[string]any {
	return map[string]any{
		"accountInfo": map[string]any{"appleId": "test@example.invalid"},
		"dsPersonId":  "123", "altDsid": "test-alt", "passwordToken": "test-token",
	}
}

func TestCommerceAccountNativeNumericFixtures(t *testing.T) {
	data, err := os.ReadFile("testdata/commerce-dsid.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Cases []struct {
			Input    string `json:"input"`
			Accepted bool   `json:"accepted"`
			Value    string `json:"value"`
		} `json:"cases"`
	}
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	if len(fixture.Cases) == 0 {
		t.Fatal("missing native fixtures")
	}
	for i, test := range fixture.Cases {
		t.Run(strconv.Itoa(i), func(t *testing.T) {
			fields := commerceAccountFields()
			fields["dsPersonId"] = test.Input
			account, err := (&CommerceResponse{Fields: fields}).ExtractAccount()
			if (err == nil) != test.Accepted {
				t.Fatal("Go acceptance differs from native execution")
			}
			if test.Accepted && strconv.FormatUint(account.DSID, 10) != test.Value {
				t.Fatal("Go value differs from native execution")
			}
			if !test.Accepted {
				var malformed *CommerceAccountError
				if account != nil || !errors.As(err, &malformed) || malformed.Field != "dsPersonId" {
					t.Fatal("unexpected numeric failure result")
				}
			}
		})
	}
}

func TestCommerceAccountUsernameFallbacks(t *testing.T) {
	for _, test := range []struct {
		name     string
		info     any
		person   any
		want     string
		badField string
	}{
		{"appleId first", map[string]any{"appleId": "first", "accountName": "second"}, map[string]any{"acAccountName": "third"}, "first", ""},
		{"accountName fallback", map[string]any{"appleId": uint64(1), "accountName": "second"}, nil, "second", ""},
		{"person fallback", map[string]any{"accountName": false}, map[string]any{"acAccountName": "third"}, "third", ""},
		{"empty string present", map[string]any{"appleId": "", "accountName": "second"}, nil, "", ""},
		{"missing name", map[string]any{}, nil, "", "username"},
		{"wrong person type", map[string]any{}, []string{"third"}, "", "username"},
		{"missing info despite person", nil, map[string]any{"acAccountName": "third"}, "", "accountInfo"},
		{"wrong info type despite person", "invalid", map[string]any{"acAccountName": "third"}, "", "accountInfo"},
	} {
		t.Run(test.name, func(t *testing.T) {
			fields := commerceAccountFields()
			fields["accountInfo"], fields["personInfo"] = test.info, test.person
			account, err := (&CommerceResponse{Fields: fields}).ExtractAccount()
			if test.badField != "" {
				var malformed *CommerceAccountError
				if account != nil || !errors.As(err, &malformed) || malformed.Field != test.badField {
					t.Fatal("unexpected identity failure result")
				}
				return
			}
			if err != nil || account.Username != test.want {
				t.Fatal("unexpected username fallback")
			}
		})
	}
}

func TestCommerceAccountWireTypesAndOptionalToken(t *testing.T) {
	for _, format := range []int{plist.XMLFormat, plist.BinaryFormat} {
		for _, mode := range []string{"token", "missing token", "wrong token type", "empty strings", "numeric DSID", "missing alt", "wrong alt type", "challenge only", "challenge with fields"} {
			t.Run(fmt.Sprintf("%d/%s", format, mode), func(t *testing.T) {
				fields := commerceAccountFields()
				wantToken, bad := true, ""
				switch mode {
				case "missing token":
					delete(fields, "passwordToken")
					wantToken = false
				case "wrong token type":
					fields["passwordToken"], wantToken = uint64(1), false
				case "empty strings":
					fields["altDsid"], fields["passwordToken"] = "", ""
				case "numeric DSID":
					fields["dsPersonId"], bad = uint64(123), "dsPersonId"
				case "missing alt":
					delete(fields, "altDsid")
					bad = "altDsid"
				case "wrong alt type":
					fields["altDsid"], bad = false, "altDsid"
				case "challenge only":
					fields = map[string]any{"failureType": "unmapped-challenge", "customerMessage": "test-private"}
					bad = "username"
				case "challenge with fields":
					// Extraction deliberately does not classify status/failureType.
					fields["failureType"] = "unmapped-challenge"
				}
				encoded, err := plist.Marshal(fields, format)
				if err != nil {
					t.Fatal(err)
				}
				var decoded map[string]any
				if _, err := plist.Unmarshal(encoded, &decoded); err != nil {
					t.Fatal(err)
				}
				response := &CommerceResponse{Fields: decoded}
				account, err := response.ExtractAccount()
				if bad != "" {
					var malformed *CommerceAccountError
					if account != nil || !errors.As(err, &malformed) || malformed.Field != bad || strings.Contains(err.Error(), "test-private") {
						t.Fatal("unexpected malformed field handling")
					}
					return
				}
				if err != nil || account.HasPasswordToken != wantToken || account.DSID != 123 {
					t.Fatal("unexpected extracted account")
				}
				if wantToken && account.PasswordToken != fields["passwordToken"] {
					t.Fatal("token not preserved")
				}
				if !wantToken && account.PasswordToken != "" {
					t.Fatal("invalid token was coerced to a string")
				}
				if mode == "challenge with fields" && response.Fields["failureType"] != "unmapped-challenge" {
					t.Fatal("challenge removed during extraction")
				}
				for _, verb := range []string{"%v", "%+v", "%#v", "%s"} {
					if fmt.Sprintf(verb, account) != "CommerceAccount{redacted}" {
						t.Fatal("account formatting is not redacted")
					}
				}
				account.Username = "changed"
				if decoded["accountInfo"].(map[string]any)["appleId"] != "test@example.invalid" {
					t.Fatal("extraction mutated response")
				}
			})
		}
	}
}

func TestCommerceAccountNilResponse(t *testing.T) {
	account, err := (*CommerceResponse)(nil).ExtractAccount()
	var malformed *CommerceAccountError
	if account != nil || !errors.As(err, &malformed) || malformed.Field != "response" {
		t.Fatal("unexpected nil response handling")
	}
}
