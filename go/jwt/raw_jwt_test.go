// Copyright 2021 Google LLC
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
///////////////////////////////////////////////////////////////////////////////

package jwt_test

import (
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/tink/go/jwt"
)

const (
	invalidUTF8     = "\xF4\x7F\xBF\xBF"
	validExpiration = 1640043004
)

type testCase struct {
	tag   string
	opts  *jwt.RawJWTOptions
	json  string
	token *jwt.RawJWT
}

func refString(a string) *string {
	return &a
}

func refTime(ts int64) *time.Time {
	t := time.Unix(ts, 0)
	return &t
}

func TestCreatingRawJWTWithAllClaims(t *testing.T) {
	json := `{
				"sub": "tink-test-subject",
				"iss": "tink-test-issuer",
				"jti": "tink-jwt-id",
				"aud": ["aud-1", "aud-2"],
				"exp": 457888,
				"nbf": 450888,
				"iat": 400888,
				"cc-num": 1.67,
				"cc-bool": true,
				"cc-null": null,
				"cc-array": [1,2,3],
				"cc-string": "cc-val",
				"cc-object": {"nested-cc-num": 5.5}
			}`

	opts := &jwt.RawJWTOptions{
		TypeHeader: refString("typeHeader"),
		Subject:    refString("tink-test-subject"),
		Issuer:     refString("tink-test-issuer"),
		JWTID:      refString("tink-jwt-id"),
		Audiences:  []string{"aud-1", "aud-2"},
		ExpiresAt:  refTime(457888),
		NotBefore:  refTime(450888),
		IssuedAt:   refTime(400888),
		CustomClaims: map[string]interface{}{
			"cc-num":    1.67,
			"cc-bool":   true,
			"cc-null":   nil,
			"cc-string": "cc-val",
			"cc-array":  []interface{}{1.0, 2.0, 3.0},
			"cc-object": map[string]interface{}{"nested-cc-num": 5.5},
		},
	}
	fromJSON, err := jwt.NewRawJWTFromJSON(refString("typeHeader"), []byte(json))
	if err != nil {
		t.Fatalf("jwt.NewRawJWTFromJSON(%q): %v", json, err)
	}
	fromOpts, err := jwt.NewRawJWT(opts)
	if err != nil {
		t.Fatalf("jwt.NewRawJWT(%v): %v", opts, err)
	}
	for _, tc := range []testCase{
		{
			tag:   "jwt.NewRawJWTFromJSON",
			token: fromJSON,
		},
		{
			tag:   "NewRawJWT",
			token: fromOpts,
		},
	} {
		if !tc.token.HasTypeHeader() {
			t.Errorf("tc.token.HasTypeHeader() = false, want true")
		}
		if !tc.token.HasAudiences() {
			t.Errorf("tc.token.HasAudiences() = false, want true")
		}
		if !tc.token.HasSubject() {
			t.Errorf("tc.token.HasSubject() = false, want true")
		}
		if !tc.token.HasIssuer() {
			t.Errorf("tc.token.HasIssuer() = false, want true")
		}
		if !tc.token.HasJWTID() {
			t.Errorf("tc.token.HasJWTID() = false, want true")
		}
		if !tc.token.HasExpiration() {
			t.Errorf("tc.token.HasExpiration() = false, want true")
		}
		if !tc.token.HasNotBefore() {
			t.Errorf("tc.token.HasNotBefore() = false, want true")
		}
		if !tc.token.HasIssuedAt() {
			t.Errorf("tc.token.HasIssuedAt() = false, want true")
		}

		typeHeader, err := tc.token.TypeHeader()
		if err != nil {
			t.Errorf("tc.token.TypeHeader() err = %v, want nil", err)
		}
		if !cmp.Equal(typeHeader, *opts.TypeHeader) {
			t.Errorf("tc.token.TypeHeader() = %q, want %q", typeHeader, *opts.TypeHeader)
		}
		audiences, err := tc.token.Audiences()
		if err != nil {
			t.Errorf("tc.token.Audiences() err = %v, want nil", err)
		}
		if !cmp.Equal(audiences, opts.Audiences) {
			t.Errorf("tc.token.Audiences() = %q, want %q", audiences, opts.Audiences)
		}
		subject, err := tc.token.Subject()
		if err != nil {
			t.Errorf("tc.token.Subject() err = %v, want nil", err)
		}
		if !cmp.Equal(subject, *opts.Subject) {
			t.Errorf("tc.token.Subject() = %q, want %q", subject, *opts.Subject)
		}
		issuer, err := tc.token.Issuer()
		if err != nil {
			t.Errorf("tc.token.Issuer() err = %v, want nil", err)
		}
		if !cmp.Equal(issuer, *opts.Issuer) {
			t.Errorf("tc.token.Issuer() = %q, want %q", issuer, *opts.Issuer)
		}
		jwtID, err := tc.token.JWTID()
		if err != nil {
			t.Errorf("tc.token.JWTID() err = %v, want nil", err)
		}
		if !cmp.Equal(jwtID, *opts.JWTID) {
			t.Errorf("tc.token.JWTID() = %q, want %q", jwtID, *opts.JWTID)
		}
		expiresAt, err := tc.token.ExpiresAt()
		if err != nil {
			t.Errorf("tc.token.ExpiresAt() err = %v, want nil", err)
		}
		if !cmp.Equal(expiresAt, *opts.ExpiresAt) {
			t.Errorf("tc.token.ExpiresAt() = %q, want %q", expiresAt, *opts.ExpiresAt)
		}
		issuedAt, err := tc.token.IssuedAt()
		if err != nil {
			t.Errorf("tc.token.IssuedAt() err = %v, want nil", err)
		}
		if !cmp.Equal(issuedAt, *opts.IssuedAt) {
			t.Errorf("tc.token.IssuedAt() = %q, want %q", issuedAt, *opts.IssuedAt)
		}
		notBefore, err := tc.token.NotBefore()
		if err != nil {
			t.Errorf("tc.token.NotBefore() err = %v, want nil", err)
		}
		if !cmp.Equal(notBefore, *opts.NotBefore) {
			t.Errorf("tc.token.NotBefore() = %q, want %q", notBefore, *opts.NotBefore)
		}
		wantCustomClaims := []string{"cc-num", "cc-bool", "cc-null", "cc-string", "cc-array", "cc-object"}
		if !cmp.Equal(tc.token.CustomClaimNames(), wantCustomClaims, cmpopts.SortSlices(func(a, b string) bool { return a < b })) {
			t.Errorf("tc.token.CustomClaimNames() = %q, want %q", tc.token.CustomClaimNames(), wantCustomClaims)
		}
		if !tc.token.HasNumberClaim("cc-num") {
			t.Errorf("tc.token.HasNumberClaim('cc-num') = false, want true")
		}
		if !tc.token.HasBooleanClaim("cc-bool") {
			t.Errorf("tc.token.HasBooleanClaim('cc-bool') = false, want true")
		}
		if !tc.token.HasNullClaim("cc-null") {
			t.Errorf("tc.token.HasNullClaim('cc-null') = false, want true")
		}
		if !tc.token.HasStringClaim("cc-string") {
			t.Errorf("tc.token.HasStringClaim('cc-string') = false, want true")
		}
		if !tc.token.HasArrayClaim("cc-array") {
			t.Errorf("tc.token.HasArrayClaim('cc-array') = false, want true")
		}
		if !tc.token.HasObjectClaim("cc-object") {
			t.Errorf("tc.token.HasObjectClaim('cc-object') = false, want true")
		}

		number, err := tc.token.NumberClaim("cc-num")
		if err != nil {
			t.Errorf("tc.token.NumberClaim('cc-num') err = %v, want nil", err)
		}
		if !cmp.Equal(number, opts.CustomClaims["cc-num"]) {
			t.Errorf("tc.token.NumberClaim('cc-num') = %f, want %f", number, opts.CustomClaims["cc-num"])
		}
		boolean, err := tc.token.BooleanClaim("cc-bool")
		if err != nil {
			t.Errorf("tc.token.BooleanClaim('cc-bool') err = %v, want nil", err)
		}
		if !cmp.Equal(boolean, opts.CustomClaims["cc-bool"]) {
			t.Errorf("tc.token.BooleanClaim('cc-bool') = %v, want %v", boolean, opts.CustomClaims["cc-bool"])
		}
		str, err := tc.token.StringClaim("cc-string")
		if err != nil {
			t.Errorf("tc.token.StringClaim('cc-string') err = %v, want nil", err)
		}
		if !cmp.Equal(str, opts.CustomClaims["cc-string"]) {
			t.Errorf("tc.token.StringClaim('cc-string') = %q, want %q", str, opts.CustomClaims["cc-string"])
		}
		array, err := tc.token.ArrayClaim("cc-array")
		if err != nil {
			t.Errorf("tc.token.ArrayClaim('cc-array') err = %v, want nil", err)
		}
		if !cmp.Equal(array, opts.CustomClaims["cc-array"]) {
			t.Errorf("tc.token.ArrayClaim('cc-array') = %q, want %q", array, opts.CustomClaims["cc-array"])
		}
		object, err := tc.token.ObjectClaim("cc-object")
		if err != nil {
			t.Errorf("tc.token.ObjectClaim('cc-object') err = %v, want nil", err)
		}
		if !cmp.Equal(object, opts.CustomClaims["cc-object"]) {
			t.Errorf("tc.token.ObjectClaim('cc-object') = %q, want %q", object, opts.CustomClaims["cc-object"])
		}
	}
}

func TestGeneratingRawJWTWithoutClaims(t *testing.T) {
	jsonToken, err := jwt.NewRawJWTFromJSON(nil, []byte("{}"))
	if err != nil {
		t.Fatalf("jwt.NewRawJWTFromJSON({}): %v", err)
	}
	optsToken, err := jwt.NewRawJWT(&jwt.RawJWTOptions{WithoutExpiration: true})
	if err != nil {
		t.Fatalf("NewRawJWT with no claims: %v", err)
	}
	for _, tc := range []testCase{
		{
			tag:   "jwt.NewRawJWTFromJSON",
			token: jsonToken,
		},
		{
			tag:   "NewRawJWT",
			token: optsToken,
		},
	} {
		if tc.token.HasTypeHeader() {
			t.Errorf("tc.token.HasTypeHeader() = true, want false")
		}
		if tc.token.HasAudiences() {
			t.Errorf("tc.token.HasAudiences() = true, want false")
		}
		if tc.token.HasSubject() {
			t.Errorf("tc.token.HasSubject() = true, want false")
		}
		if tc.token.HasIssuer() {
			t.Errorf("tc.token.HasIssuer() = true, want false")
		}
		if tc.token.HasJWTID() {
			t.Errorf("tc.token.HasJWTID() = true, want false")
		}
		if tc.token.HasExpiration() {
			t.Errorf("tc.token.HasExpiration() = true, want false")
		}
		if tc.token.HasNotBefore() {
			t.Errorf("tc.token.HasNotBefore() = true, want false")
		}
		if tc.token.HasIssuedAt() {
			t.Errorf("tc.token.HasIssuedAt() = true, want false")
		}
		if _, err := tc.token.Audiences(); err == nil {
			t.Errorf("tc.token.Audiences() err = nil, want error")
		}
		if _, err := tc.token.Subject(); err == nil {
			t.Errorf("tc.token.Subject() err = nil, want error")
		}
		if _, err := tc.token.Issuer(); err == nil {
			t.Errorf("tc.token.Issuer() err = nil, want error")
		}
		if _, err := tc.token.JWTID(); err == nil {
			t.Errorf("tc.token.JWTID() err = nil, want error")
		}
		if _, err := tc.token.ExpiresAt(); err == nil {
			t.Errorf("tc.token.ExpiresAt() err = nil, want error")
		}
		if _, err := tc.token.IssuedAt(); err == nil {
			t.Errorf("tc.token.IssuedAt() err = nil, want error")
		}
		if _, err := tc.token.NotBefore(); err == nil {
			t.Errorf("tc.token.NotBefore() err = nil, want error")
		}
		if !cmp.Equal(tc.token.CustomClaimNames(), []string{}) {
			t.Errorf("tc.token.CustomClaimNames() = %q want %q", tc.token.CustomClaimNames(), []string{})
		}
	}
}

func TestNewRawJWTLargeValidTimestamps(t *testing.T) {
	opts := &jwt.RawJWTOptions{
		TypeHeader: refString("typeHeader"),
		ExpiresAt:  refTime(253402300799),
		NotBefore:  refTime(253402300700),
		IssuedAt:   refTime(253402300000),
	}
	token, err := jwt.NewRawJWT(opts)
	if err != nil {
		t.Fatalf("generating RawJWT with valid timestamps (%q, %q, %q): %v", opts.ExpiresAt, opts.NotBefore, opts.IssuedAt, err)
	}
	expiresAt, err := token.ExpiresAt()
	if err != nil {
		t.Errorf("tc.token.ExpiresAt() err = %v, want nil", err)
	}
	if !cmp.Equal(expiresAt, *opts.ExpiresAt) {
		t.Errorf("tc.token.ExpiresAt() = %q want %q", expiresAt, *opts.ExpiresAt)
	}

	notBefore, err := token.NotBefore()
	if err != nil {
		t.Errorf("tc.token.NotBefore() err = %v, want nil", err)
	}
	if !cmp.Equal(notBefore, *opts.NotBefore) {
		t.Errorf("tc.token.NotBefore() = %q want %q", notBefore, *opts.NotBefore)
	}

	issuedAt, err := token.IssuedAt()
	if err != nil {
		t.Errorf("tc.token.IssuedAt() err = %v, want nil", err)
	}
	if !cmp.Equal(issuedAt, *opts.IssuedAt) {
		t.Errorf("tc.token.IssuedAt() = %q want %q", issuedAt, *opts.IssuedAt)
	}
}

func TestNewRawJWTSingleStringAudience(t *testing.T) {
	opts := &jwt.RawJWTOptions{
		WithoutExpiration: true,
		Audience:          refString("tink-aud"),
	}
	rawJWT, err := jwt.NewRawJWT(opts)
	if err != nil {
		t.Fatalf("generating RawJWT with a single audience: %v", err)
	}
	aud, err := rawJWT.Audiences()
	if err != nil {
		t.Errorf("getting audience from token: %v", err)
	}
	want := []string{*opts.Audience}
	if !cmp.Equal(aud, want) {
		t.Errorf("rawJWT.Audiences() = %q, want %q", aud, want)
	}
}

func TestSingleStringAudienceFromJSON(t *testing.T) {
	rawJWT, err := jwt.NewRawJWTFromJSON(nil, []byte(`{"aud": "tink-aud"}`))
	if err != nil {
		t.Fatalf("parsing valid RawJWT: %v", err)
	}
	aud, err := rawJWT.Audiences()
	if err != nil {
		t.Errorf("getting audience from token: %v", err)
	}
	want := []string{"tink-aud"}
	if !cmp.Equal(aud, want) {
		t.Errorf("rawJWT.Audiences() = %q, want %q", aud, want)
	}
}

func TestNewRawJWTValidationFailures(t *testing.T) {
	testCases := []testCase{
		{
			tag: "empty jwt.RawJWTOptions options fails",
		},
		{
			tag: "no ExpiresAt specified and WithoutExpiration = false fails",
			opts: &jwt.RawJWTOptions{
				Audiences: []string{"tink-foo"},
			},
		},
		{
			tag: "ExpiresAt and WithoutExpiration = true fails",
			opts: &jwt.RawJWTOptions{
				Audiences:         []string{"tink-foo"},
				ExpiresAt:         refTime(validExpiration),
				WithoutExpiration: true,
			},
		},
		{
			tag: "specifying Audenience and Audiences fails",
			opts: &jwt.RawJWTOptions{
				Audiences:         []string{"tink-foo"},
				Audience:          refString("tink-bar"),
				WithoutExpiration: true,
			},
		},
		{
			tag: "empty audiences array fails",
			opts: &jwt.RawJWTOptions{
				ExpiresAt: refTime(validExpiration),
				Audiences: []string{},
			},
		},
		{
			tag: "audiences with invalid UTF-8 string fails",
			opts: &jwt.RawJWTOptions{
				WithoutExpiration: true,
				Audiences:         []string{"valid", invalidUTF8},
			},
		},
		{
			tag: "custom claims containing registered subject claims fails",
			opts: &jwt.RawJWTOptions{
				Audiences: []string{"tink-foo"},
				ExpiresAt: refTime(validExpiration),
				CustomClaims: map[string]interface{}{
					"sub": "overwrite",
				},
			},
		},
		{
			tag: "custom claims containing registered issuer claims fails",
			opts: &jwt.RawJWTOptions{
				Audiences: []string{"tink-foo"},
				ExpiresAt: refTime(validExpiration),
				CustomClaims: map[string]interface{}{
					"iss": "overwrite",
				},
			},
		},
		{
			tag: "custom claims containing registered jwt id claims fails",
			opts: &jwt.RawJWTOptions{
				Audiences: []string{"tink-foo"},
				ExpiresAt: refTime(validExpiration),
				CustomClaims: map[string]interface{}{
					"jti": "overwrite",
				},
			},
		},
		{
			tag: "custom claims containing registered expiration claims fails",
			opts: &jwt.RawJWTOptions{
				Audiences: []string{"tink-foo"},
				ExpiresAt: refTime(validExpiration),
				CustomClaims: map[string]interface{}{
					"exp": "overwrite",
				},
			},
		},
		{
			tag: "custom claims containing registered audience claims fails",
			opts: &jwt.RawJWTOptions{
				Audiences:         []string{"tink-foo"},
				WithoutExpiration: true,
				CustomClaims: map[string]interface{}{
					"aud": []interface{}{"overwrite"},
				},
			},
		},
		{
			tag: "custom claims with non standard JSON types fails",
			opts: &jwt.RawJWTOptions{
				Audiences: []string{"tink-foo"},
				ExpiresAt: refTime(validExpiration),
				CustomClaims: map[string]interface{}{
					"complex": time.Time{},
				},
			},
		},
		{
			tag: "non UTF-8 string on isser claim fails",
			opts: &jwt.RawJWTOptions{
				Audiences: []string{"tink-foo"},
				ExpiresAt: refTime(validExpiration),
				Issuer:    refString(invalidUTF8),
			},
		},
		{
			tag: "non UTF-8 string on subject claim fails",
			opts: &jwt.RawJWTOptions{
				Audiences:         []string{"tink-foo"},
				WithoutExpiration: true,
				Subject:           refString(invalidUTF8),
			},
		},
		{
			tag: "non UTF-8 string on JWT ID claim fails",
			opts: &jwt.RawJWTOptions{
				Audiences:         []string{"tink-foo"},
				WithoutExpiration: true,
				JWTID:             refString(invalidUTF8),
			},
		},
		{
			tag: "non UTF-8 string on custom claim fails",
			opts: &jwt.RawJWTOptions{
				Audiences: []string{"tink-foo"},
				Issuer:    refString("ise-testing"),
				ExpiresAt: refTime(validExpiration),
				CustomClaims: map[string]interface{}{
					"esoteric": invalidUTF8,
				},
			},
		},
		{
			tag: "issued at timestamp greater than valid JWT max time fails",
			opts: &jwt.RawJWTOptions{
				Audiences: []string{"tink-foo"},
				ExpiresAt: refTime(validExpiration),
				IssuedAt:  refTime(253402300800),
			},
		},
		{
			tag: "expires at timestamp greater than valid JWT max time fails",
			opts: &jwt.RawJWTOptions{
				Audiences: []string{"tink-foo"},
				ExpiresAt: refTime(253402300800),
			},
		},
		{
			tag: "not before timestamp smaller than valid JWT min time fails",
			opts: &jwt.RawJWTOptions{
				Audiences: []string{"tink-foo"},
				ExpiresAt: refTime(validExpiration),
				NotBefore: refTime(-5),
			},
		},
	}
	for _, tc := range testCases {
		t.Run(tc.tag, func(t *testing.T) {
			_, err := jwt.NewRawJWT(tc.opts)
			if err == nil {
				t.Errorf("expected error instead got nil")
			}
		})
	}
}

func TestJSONPayload(t *testing.T) {
	for _, tc := range []testCase{
		{
			tag: "subject",
			opts: &jwt.RawJWTOptions{
				WithoutExpiration: true,
				Subject:           refString("tink-subject"),
			},
			json: `{"sub":"tink-subject"}`,
		},
		{
			tag: "audience list",
			opts: &jwt.RawJWTOptions{
				WithoutExpiration: true,
				Audiences:         []string{"one"},
			},
			json: `{"aud":["one"]}`,
		},
		{
			tag: "audience string",
			opts: &jwt.RawJWTOptions{
				WithoutExpiration: true,
				Audience:          refString("one"),
			},
			json: `{"aud":"one"}`,
		},
		{
			tag: "issuer",
			opts: &jwt.RawJWTOptions{
				WithoutExpiration: true,
				Issuer:            refString("tink-test"),
			},
			json: `{"iss":"tink-test"}`,
		},
		{
			tag: "jwt id",
			opts: &jwt.RawJWTOptions{
				WithoutExpiration: true,
				JWTID:             refString("tink-id"),
			},
			json: `{"jti":"tink-id"}`,
		},
		{
			tag: "issued at",
			opts: &jwt.RawJWTOptions{
				WithoutExpiration: true,
				IssuedAt:          refTime(78324),
			},
			json: `{"iat":78324}`,
		},
		{
			tag: "not before",
			opts: &jwt.RawJWTOptions{
				WithoutExpiration: true,
				NotBefore:         refTime(78324),
			},
			json: `{"nbf":78324}`,
		},
		{
			tag: "expiration",
			opts: &jwt.RawJWTOptions{
				ExpiresAt: refTime(78324),
			},
			json: `{"exp":78324}`,
		},
		{
			tag: "custom-claim",
			opts: &jwt.RawJWTOptions{
				WithoutExpiration: true,
				CustomClaims: map[string]interface{}{
					"cust": []interface{}{map[string]interface{}{"key": "val"}},
				},
			},
			json: `{"cust":[{"key":"val"}]}`,
		},
		{
			tag: "no claims",
			opts: &jwt.RawJWTOptions{
				WithoutExpiration: true,
			},
			json: `{}`,
		},
	} {
		t.Run(tc.tag, func(t *testing.T) {
			token, err := jwt.NewRawJWT(tc.opts)
			if err != nil {
				t.Errorf("generating valid RawJWT: %v", err)
			}
			j, err := token.JSONPayload()
			if err != nil {
				t.Errorf("calling JSONPayload() on rawJWT: %v", err)
			}
			if !cmp.Equal(string(j), tc.json) {
				t.Fatalf("JSONPayload output got %v, expected %v", string(j), tc.json)
			}
		})
	}
}

func TestFromJSONValidationFailures(t *testing.T) {
	testCases := []testCase{
		{
			tag:  "json with empty audience",
			json: `{"sub": "tink", "aud": []}`,
		},
		{
			tag:  "json with audience of wrong type",
			json: `{"aud": 5}`,
		},
		{
			tag:  "json with audiences of wrong type",
			json: `{"aud": ["one", null]}`,
		},
		{
			tag:  "json with registered claim with wrong type",
			json: `{"sub": 1}`,
		},
		{
			tag:  "json with non UTF-8 string on subject claim fails",
			json: `{"sub": "\xF4\x7F\xBF\xBF"}`,
		},
		{
			tag:  "json with non UTF-8 string on issuer claim fails",
			json: `{"iss": "\xF4\x7F\xBF\xBF"}`,
		},
		{
			tag:  "json with non UTF-8 string on jwt id claim fails",
			json: `{"jti": "\xF4\x7F\xBF\xBF"}`,
		},
		{
			tag:  "json with `not before` timestamp claim greater than valid JWT max time fails",
			json: `{"nbf": 253402301799}`,
		},
		{
			tag:  "json with `issued at` timestamp claim greater than valid JWT max time fails",
			json: `{"iat": 253402301799}`,
		},
		{
			tag:  "json with `expiration` timestamp claim greater than valid JWT max time fails",
			json: `{"exp": 253402301799}`,
		},
		{
			tag:  "json with `not before` timestamp claim smaller than valid JWT min time fails",
			json: `{"nbf": -4}`,
		},
		{
			tag:  "json with `issued at` timestamp claim smaller than valid JWT min time fails",
			json: `{"iat": -4}`,
		},
		{
			tag:  "json with `expiration` timestamp claim smaller than valid JWT min time fails",
			json: `{"exp": -4}`,
		},
		{
			tag:  "json with `not before` claim of non numeric type fails",
			json: `{"nbf": "invalid"}`,
		},
		{
			tag:  "json with `issued at` claim of non numeric type fails",
			json: `{"iat": "invalid"}`,
		},
		{
			tag:  "json with `expiration` claim of non numeric type fails",
			json: `{"exp": "invalid"}`,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.tag, func(t *testing.T) {
			if _, err := jwt.NewRawJWTFromJSON(nil, []byte(tc.json)); err == nil {
				t.Errorf("expected error instead got nil")
			}
		})
	}
}

func TestHasCustomClaimsOfKind(t *testing.T) {
	opts := &jwt.RawJWTOptions{
		TypeHeader:        refString("typeHeader"),
		WithoutExpiration: true,
		CustomClaims: map[string]interface{}{
			"cc-num":    1.67,
			"cc-bool":   false,
			"cc-nil":    nil,
			"cc-list":   []interface{}{1.0, 2.0, 3.0},
			"cc-string": "cc-val",
			"cc-object": map[string]interface{}{
				"nested-cc-num": 5.5,
			},
		},
	}
	token, err := jwt.NewRawJWT(opts)
	if err != nil {
		t.Fatalf("generating valid RawJWT: %v", err)
	}
	if token.HasBooleanClaim("cc-num") {
		t.Errorf("custom number claim 'cc-num' should return false when queried for another type")
	}
	if token.HasNullClaim("cc-bool") {
		t.Errorf("custom boolean claim 'cc-bool' should return false when queried for another type")
	}
	if token.HasNumberClaim("cc-bool") {
		t.Errorf("custom boolean claim 'cc-bool' should return false when queried for another type")
	}
	if token.HasStringClaim("cc-bool") {
		t.Errorf("custom boolean claim 'cc-bool' should return false when queried for another type")
	}
	if token.HasArrayClaim("cc-bool") {
		t.Errorf("custom boolean claim 'cc-bool' should return false when queried for another type")
	}
	if token.HasObjectClaim("cc-bool") {
		t.Errorf("custom boolean claim 'cc-bool' should return false when queried for another type")
	}
}

func TestGettingRegisteredClaimsThroughCustomFails(t *testing.T) {
	opts := &jwt.RawJWTOptions{
		TypeHeader: refString("typeHeader"),
		Subject:    refString("tink-test-subject"),
		Issuer:     refString("tink-test-issuer"),
		JWTID:      refString("tink-jwt-id-1"),
		Audiences:  []string{"aud-1", "aud-2"},
		ExpiresAt:  refTime(validExpiration),
		IssuedAt:   refTime(validExpiration - 100),
		NotBefore:  refTime(validExpiration - 50),
	}
	token, err := jwt.NewRawJWT(opts)
	if err != nil {
		t.Fatalf("generating valid RawJWT: %v", err)
	}
	if !cmp.Equal(token.CustomClaimNames(), []string{}) {
		t.Errorf("tc.token.CustomClaimNames() = %q want %q", token.CustomClaimNames(), []string{})
	}
	for _, c := range []string{"sub", "iss", "aud", "nbf", "exp", "iat", "jti"} {
		if token.HasNullClaim(c) {
			t.Errorf("registered '%q' claim should return false when calling HasNullClaim", c)
		}
		if token.HasBooleanClaim(c) {
			t.Errorf("registered '%q' claim should return false when calling HasBooleanClaim", c)
		}
		if _, err := token.BooleanClaim(c); err == nil {
			t.Errorf("expected error when calling token.BoolClaim(%q) instead got nil", c)
		}
		if token.HasNumberClaim(c) {
			t.Errorf("registered '%q' claim should return false when calling HasNumberClaim", c)
		}
		if _, err := token.NumberClaim(c); err == nil {
			t.Errorf("expected error when calling token.NumberClaim(%q) instead got nil", c)
		}
		if token.HasStringClaim(c) {
			t.Errorf("registered '%q' claim should return false when calling HasStringClaim", c)
		}
		if _, err := token.StringClaim(c); err == nil {
			t.Errorf("expected error when calling token.StringClaim(%q) instead got nil", c)
		}
		if token.HasArrayClaim(c) {
			t.Errorf("registered '%q' claim should return false when calling HasArrayClaim", c)
		}
		if _, err := token.ArrayClaim(c); err == nil {
			t.Errorf("expected error when calling token.ListClaim(%q) instead got nil", c)
		}
		if token.HasObjectClaim(c) {
			t.Errorf("registered '%q' claim should return false when calling HasObjectClaim", c)
		}
		if _, err := token.ObjectClaim(c); err == nil {
			t.Errorf("expected error when calling token.JSONClaim(%q) instead got nil", c)
		}
	}
}
