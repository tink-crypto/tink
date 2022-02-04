// Copyright 2022 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
////////////////////////////////////////////////////////////////////////////////

package jwt

import (
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"

	tpb "github.com/google/tink/go/proto/tink_go_proto"
)

func TestKIDForNonTinkKeysIsNil(t *testing.T) {
	for _, op := range []tpb.OutputPrefixType{
		tpb.OutputPrefixType_LEGACY,
		tpb.OutputPrefixType_RAW,
		tpb.OutputPrefixType_CRUNCHY} {
		if kid := keyID(1234, op); kid != nil {
			t.Errorf("keyID(1234, %q) = %q, want nil", op, *kid)
		}
	}
}

func TestKeyIDForTinkKey(t *testing.T) {
	want := "GsapRA"
	kid := keyID(0x1ac6a944, tpb.OutputPrefixType_TINK)
	if kid == nil {
		t.Errorf("KeyID(0x1ac6a944, %q) = nil, want %q", tpb.OutputPrefixType_TINK, want)
	}
	if kid != nil && !cmp.Equal(*kid, want) {
		t.Errorf("KeyID(0x1ac6a944, %q) = %q, want %q", tpb.OutputPrefixType_TINK, *kid, want)
	}
}

type payloadTestCase struct {
	tag       string
	rawJWT    *RawJWT
	opts      *RawJWTOptions
	tinkKID   *string
	customKID *string
	algorithm string
}

func refString(a string) *string {
	return &a
}

func refTime(ts int64) *time.Time {
	t := time.Unix(ts, 0)
	return &t
}

func TestBase64Encode(t *testing.T) {
	// Examples from: https://datatracker.ietf.org/doc/html/rfc7515#appendix-A.1.1
	want := "eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ"
	payload := []byte{123, 34, 105, 115, 115, 34, 58, 34, 106, 111, 101, 34, 44, 13, 10, 32, 34, 101, 120, 112, 34, 58, 49, 51, 48, 48, 56, 49, 57, 51, 56,
		48, 44, 13, 10, 32, 34, 104, 116, 116, 112, 58, 47, 47, 101, 120, 97, 109, 112, 108, 101, 46, 99, 111, 109, 47, 105, 115, 95, 114, 111, 111, 116, 34, 58, 116, 114, 117, 101, 125}
	got := base64Encode(payload)
	if got != want {
		t.Errorf("base64Encode() got %q want %q", got, want)
	}
}

func TestBase64Decode(t *testing.T) {
	// Examples from: https://datatracker.ietf.org/doc/html/rfc7515#appendix-A.1.1
	want := []byte{123, 34, 105, 115, 115, 34, 58, 34, 106, 111, 101, 34, 44, 13, 10, 32, 34, 101, 120, 112, 34, 58, 49, 51, 48, 48, 56, 49, 57, 51, 56,
		48, 44, 13, 10, 32, 34, 104, 116, 116, 112, 58, 47, 47, 101, 120, 97, 109, 112, 108, 101, 46, 99, 111, 109, 47, 105, 115, 95, 114, 111, 111, 116, 34, 58, 116, 114, 117, 101, 125}
	got, err := base64Decode("eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ")
	if err != nil {
		t.Errorf("base64Decode() err = %v, want nil", err)
	}
	if !cmp.Equal(got, want) {
		t.Errorf("base64Decode() got %q, want %q", got, want)
	}
}

func TestInvalidCharactersFailBase64Decode(t *testing.T) {
	if _, err := base64Decode("iLA0KIC&hD"); err == nil {
		t.Errorf("base64Decode() err = nil, want error")
	}
}

func TestEncodeStaticHeaderWithPayloadIssuerTokenForSigning(t *testing.T) {
	opts := &RawJWTOptions{
		WithoutExpiration: true,
		Issuer:            refString("tink-issuer"),
	}
	// Header 'RS256' alg from: https://datatracker.ietf.org/doc/html/rfc7515#appendix-A.2.1
	// Payload: `{"iss":"tink-issuer"}`
	wantUnsigned := "eyJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJ0aW5rLWlzc3VlciJ9"
	rawJWT, err := NewRawJWT(opts)
	if err != nil {
		t.Fatalf("generating valid RawJWT: %v", err)
	}
	unsigned, err := createUnsigned(rawJWT, "RS256", nil, nil)
	if err != nil {
		t.Errorf("createUnsigned() err = %v, want nil", err)
	}

	if unsigned != wantUnsigned {
		t.Errorf("got unsigned %q, want %q", unsigned, wantUnsigned)
	}
}

func TestEncodeHeaderWithHeaderFieldsAndEmptyPayload(t *testing.T) {
	type testCase struct {
		tag                 string
		opts                *RawJWTOptions
		wantHeaderSubstring string
		customKID           *string
		tinkKID             *string
	}
	for _, tc := range []testCase{
		{
			tag: "type header",
			opts: &RawJWTOptions{
				WithoutExpiration: true,
				TypeHeader:        refString("JWT"),
			},
			wantHeaderSubstring: `"typ":"JWT"`,
		},
		{
			tag: "custom kid",
			opts: &RawJWTOptions{
				WithoutExpiration: true,
			},
			customKID:           refString("custom"),
			wantHeaderSubstring: `"kid":"custom"`,
		},
		{
			tag: "tink kid",
			opts: &RawJWTOptions{
				WithoutExpiration: true,
			},
			tinkKID:             refString("tink"),
			wantHeaderSubstring: `"kid":"tink"`,
		},
	} {
		rawJWT, err := NewRawJWT(tc.opts)
		if err != nil {
			t.Fatalf("generating valid RawJWT: %v", err)
		}
		unsigned, err := createUnsigned(rawJWT, "RS256", tc.tinkKID, tc.customKID)
		if err != nil {
			t.Errorf("createUnsigned() err = %v, want nil", err)
		}
		token := strings.Split(unsigned, ".")
		if len(token) != 2 {
			t.Errorf("token[0] not encoded in compact serialization format")
		}
		header, err := base64Decode(token[0])
		if err != nil {
			t.Errorf("base64Decode(token[0] = %q)", token[0])
		}
		if !strings.Contains(string(header), tc.wantHeaderSubstring) {
			t.Errorf("header %q, doesn't contain: %q", string(header), tc.wantHeaderSubstring)
		}
		wantPayload := "e30" // `{}`
		if string(token[1]) != wantPayload {
			t.Errorf("token[1] = %q, want %q", token[1], wantPayload)
		}
	}
}

func TestCreateUnsignedWithNilRawJWTFails(t *testing.T) {
	if _, err := createUnsigned(nil, "HS256", nil, nil); err == nil {
		t.Errorf("createUnsigned(rawJWT = nil) err = nil, want error")
	}
}

func TestCreateUnsignedCustomAndTinkKIDFail(t *testing.T) {
	rawJWT, err := NewRawJWT(&RawJWTOptions{WithoutExpiration: true})
	if err != nil {
		t.Fatalf("generating valid RawJWT: %v", err)
	}
	if _, err := createUnsigned(rawJWT, "HS256", refString("123"), refString("456")); err == nil {
		t.Errorf("createUnsigned(tinkKID = 456, customKID = 123) err = nil, want error")
	}
}

func TestCombineTokenAndSignature(t *testing.T) {
	// https://datatracker.ietf.org/doc/html/rfc7515#appendix-A.2.1
	payload := "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ"
	signature := []byte{116, 24, 223, 180, 151, 153, 224, 37, 79, 250, 96, 125, 216, 173, 187, 186, 22, 212, 37, 77, 105, 214, 191, 240, 91, 88, 5, 88, 83, 132, 141, 121}
	token := combineUnsignedAndSignature(payload, signature)
	want := "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	if !cmp.Equal(token, want) {
		t.Errorf("combineUnsignedAndSignature(%q, %q) = %q, want %q", payload, signature, token, want)
	}
}

func TestSplitSignedCompactInvalidInputs(t *testing.T) {
	type testCases struct {
		tag   string
		token string
	}
	for _, tc := range []testCases{
		{
			tag:   "empty payload",
			token: "",
		},
		{
			tag:   "not in compact serialization missing separators",
			token: "Zm9vYmFyIVRpbms",
		},
		{
			tag:   "not in compact serialization additional separators",
			token: "Zm9vYmFyIVRpbms.Zm9vYmFyGVRpbms.Zm9vYmFyIVRpbms.Zm9vYmFyINRpbms",
		},
		{
			tag:   "non web safe URL encoding character",
			token: "Zm9vYmFyIVRpbms.m9vYmFy.Zm&mFyIVRpbms",
		},
		{
			tag:   "no content",
			token: ".Zm9vYmFyIVRpbms",
		},
		{
			tag:   "no signature",
			token: "Zm9vYmFyIVRpbms.Zm9vYmFyIVRpbms.",
		},
		{
			tag:   "no signature and no content",
			token: "..",
		},
	} {
		t.Run(tc.tag, func(t *testing.T) {
			if _, _, err := splitSignedCompact(tc.token); err == nil {
				t.Errorf("splitSignedCompact(%q) err = nil, want error", tc.token)
			}
		})
	}
}

func TestSplitSignedCompact(t *testing.T) {
	// signed token from: https://datatracker.ietf.org/doc/html/rfc7515#appendix-A.1.1
	signedToken := "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	wantSig := []byte{116, 24, 223, 180, 151, 153, 224, 37, 79, 250, 96, 125, 216, 173, 187, 186, 22, 212, 37, 77, 105, 214, 191, 240, 91, 88, 5, 88, 83, 132, 141, 121}
	wantToken := "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ"
	sig, token, err := splitSignedCompact(signedToken)
	if err != nil {
		t.Errorf("splitSignedCompact(%q) err = %v, want nil", signedToken, err)
	}
	if !cmp.Equal(sig, wantSig) {
		t.Errorf("splitSignedCompact() sig = %q, want %q", sig, wantSig)
	}
	if token != wantToken {
		t.Errorf("splitSignedCompact() token = %q, want %q", token, wantToken)
	}
}

func TestDecodeValidateInvalidHeaderFailures(t *testing.T) {
	type testCases struct {
		tag       string
		header    string
		alg       string
		tinkKID   *string
		customKID *string
	}
	for _, tc := range []testCases{
		{
			tag:    "invalid JSON header",
			header: `JiVeQCo`,
		},
		{
			tag:    "contains line feed",
			header: "eyJ0eXAiOiJKV1Qi\nLA0KICJhbGciOiJIUzI1NiJ9",
			alg:    "HS256",
		},
		{
			tag:    "header contains no fields",
			header: base64Encode([]byte(`{}`)),
		},
		{
			tag:    "type header not a string",
			header: base64Encode([]byte(`{"alg":"HS256", "typ":5}`)),
			alg:    "HS256",
		},
		{
			tag:    "wrong algorithm",
			header: base64Encode([]byte(`{"alg":"HS256"}`)),
			alg:    "HS512",
		},
		{
			tag:       "specyfing custom and tink kid",
			header:    base64Encode([]byte(`{"alg":"HS256", "kid":"tink"}`)),
			alg:       "HS256",
			tinkKID:   refString("tink"),
			customKID: refString("custom"),
		},
		{
			tag:       "invalid custom kid",
			header:    base64Encode([]byte(`{"alg":"HS256", "kid":"custom"}`)),
			customKID: refString("notCustom"),
			alg:       "HS256",
		},
		{
			tag:     "invalid tink kid",
			header:  base64Encode([]byte(`{"alg":"HS256", "kid":"tink"}`)),
			tinkKID: refString("notTink"),
			alg:     "HS256",
		},
		{
			tag:     "specify tink kid and token without kig",
			header:  base64Encode([]byte(`{"alg":"HS256"}`)),
			tinkKID: refString("notTink"),
			alg:     "HS256",
		},
		{
			tag:    "crit header",
			header: base64Encode([]byte(`{"alg":"HS256", "crit":"fooBar"}`)),
			alg:    "HS256",
		},
		{
			tag:    "no compact serialization",
			header: "asd.asd",
		},
		{
			tag:    "invalid UTF16 encoding",
			header: base64Encode([]byte(`{"alg":"HS256", "typ":"\uD834"}`)),
		},
	} {
		t.Run(tc.tag, func(t *testing.T) {
			if _, err := decodeUnsignedTokenAndValidateHeader(dotConcat(tc.header, base64Encode([]byte("{}"))), tc.alg, tc.tinkKID, tc.customKID); err == nil {
				t.Errorf("decodeUnsignedTokenAndValidateHeader() err = nil, want error")
			}
		})
	}
}

func TestDecodeValidateKIDHeader(t *testing.T) {
	type testCases struct {
		tag       string
		header    string
		tinkKID   *string
		customKID *string
	}
	for _, tc := range []testCases{
		{
			tag:    "not kid header field",
			header: base64Encode([]byte(`{"alg":"HS256"}`)),
		},
		{
			tag:       "validates custom kid",
			header:    base64Encode([]byte(`{"alg":"HS256", "kid":"custom"}`)),
			customKID: refString("custom"),
		},
		{
			tag:     "validates tink kid",
			header:  base64Encode([]byte(`{"alg":"HS256", "kid":"tink"}`)),
			tinkKID: refString("tink"),
		},
		{
			tag:    "ignores kid if exists and tink kid isn't specified",
			header: base64Encode([]byte(`{"alg":"HS256", "kid":"random"}`)),
		},
		{
			tag:    "unkown headers are accepted",
			header: base64Encode([]byte(`{"alg":"HS256","unknown":"header"}`)),
		},
	} {
		t.Run(tc.tag, func(t *testing.T) {
			_, err := decodeUnsignedTokenAndValidateHeader(dotConcat(tc.header, base64Encode([]byte("{}"))), "HS256", tc.tinkKID, tc.customKID)
			if err != nil {
				t.Errorf("decodeUnsignedTokenAndValidateHeader() err = %v, want nil", err)
			}
		})
	}
}

func TestDecodeVerifyTokenFixedValues(t *testing.T) {
	header := "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9"                                                        // Header example from https://tools.ietf.org/html/rfc7519#section-3.1
	payload := "eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ" // Payload example from https://tools.ietf.org/html/rfc7519#section-3.1
	rawJWT, err := decodeUnsignedTokenAndValidateHeader(dotConcat(header, payload), "HS256", nil, nil)
	if err != nil {
		t.Errorf("decodeUnsignedTokenAndValidateHeader() err = %v, want nil", err)
	}
	iss, err := rawJWT.Issuer()
	if err != nil {
		t.Errorf("rawJWT.Issuer() err = %v, want nil", err)
	}
	if iss != "joe" {
		t.Errorf("rawJWT.Issuer() = %q, want joe", iss)
	}
	exp, err := rawJWT.ExpiresAt()
	if err != nil {
		t.Errorf("rawJWT.ExpiresAt() err = %v, want nil", err)
	}
	wantExp := time.Unix(1300819380, 0)
	if !exp.Equal(wantExp) {
		t.Errorf("rawJWT.ExpiresAt() = %q, want %q", exp, wantExp)
	}
	cc, err := rawJWT.BooleanClaim("http://example.com/is_root")
	if err != nil {
		t.Errorf("rawJWT.BooleanClaim('http://example.com/is_root') err = %v want nil", err)
	}
	if cc != true {
		t.Errorf("rawJWT.BooleanClaim('http://example.com/is_root') = %v, want true", cc)
	}
}

func TestDecodeVerifyTokenPaylodWithInvalidEndcoding(t *testing.T) {
	if _, err := decodeUnsignedTokenAndValidateHeader(dotConcat(base64Encode([]byte(`{"alg":"HS256"}`)), "_aSL&%"), "HS256", nil, nil); err == nil {
		t.Errorf("decodeUnsignedTokenAndValidateHeader() err = nil, want error")
	}
}
