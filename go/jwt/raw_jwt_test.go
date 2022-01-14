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

package jwt

import (
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"google.golang.org/protobuf/testing/protocmp"

	spb "google.golang.org/protobuf/types/known/structpb"
)

const (
	invalidUTF8     = "\xF4\x7F\xBF\xBF"
	validExpiration = 1640043004
)

type newRawJWTTestCase struct {
	tag      string
	opts     *RawJWTOptions
	expected *RawJWT
}

func refString(a string) *string {
	return &a
}

func refTime(ts int64) *time.Time {
	t := time.Unix(ts, 0)
	return &t
}

func TestNewRawJWT(t *testing.T) {
	testCases := []newRawJWTTestCase{
		{
			tag: "creates rawJWT with all fields",
			opts: &RawJWTOptions{
				TypeHeader: "typeHeader",
				Subject:    refString("tink-test-subject"),
				Issuer:     refString("tink-test-issuer"),
				JWTID:      refString("tink-jwt-id-1"),
				Audiences:  []string{"aud-1", "aud-2"},
				ExpiresAt:  refTime(validExpiration),
				IssuedAt:   refTime(validExpiration - 100),
				NotBefore:  refTime(validExpiration - 50),
				CustomClaims: map[string]interface{}{
					"cc-one": 1,
				},
			},
			expected: &RawJWT{
				typeHeader: "typeHeader",
				jsonpb: &spb.Struct{
					Fields: map[string]*spb.Value{
						"sub":    spb.NewStringValue("tink-test-subject"),
						"iss":    spb.NewStringValue("tink-test-issuer"),
						"jti":    spb.NewStringValue("tink-jwt-id-1"),
						"aud":    spb.NewListValue(&spb.ListValue{Values: []*spb.Value{spb.NewStringValue("aud-1"), spb.NewStringValue("aud-2")}}),
						"exp":    spb.NewNumberValue(float64(validExpiration)),
						"iat":    spb.NewNumberValue(float64(validExpiration - 100)),
						"nbf":    spb.NewNumberValue(float64(validExpiration - 50)),
						"cc-one": spb.NewNumberValue(1),
					},
				},
			},
		},
		{
			tag: "empty fields are omitted",
			opts: &RawJWTOptions{
				TypeHeader: "typeHeader",
				ExpiresAt:  refTime(validExpiration),
			},
			expected: &RawJWT{
				typeHeader: "typeHeader",
				jsonpb: &spb.Struct{
					Fields: map[string]*spb.Value{
						"exp": spb.NewNumberValue(float64(validExpiration)),
					},
				},
			},
		},
		{
			tag: "no claims present",
			opts: &RawJWTOptions{
				TypeHeader:        "typeHeader",
				WithoutExpiration: true,
			},
			expected: &RawJWT{
				typeHeader: "typeHeader",
				jsonpb:     &spb.Struct{},
			},
		},
		{
			tag: "without expiration option",
			opts: &RawJWTOptions{
				TypeHeader:        "typeHeader",
				WithoutExpiration: true,
				Subject:           refString("no expiration"),
			},
			expected: &RawJWT{
				typeHeader: "typeHeader",
				jsonpb: &spb.Struct{
					Fields: map[string]*spb.Value{
						"sub": spb.NewStringValue("no expiration"),
					},
				},
			},
		},
		{
			tag: "large expiration",
			opts: &RawJWTOptions{
				TypeHeader: "typeHeader",
				ExpiresAt:  refTime(253402300799),
			},
			expected: &RawJWT{
				typeHeader: "typeHeader",
				jsonpb: &spb.Struct{
					Fields: map[string]*spb.Value{
						"exp": spb.NewNumberValue(float64(253402300799)),
					},
				},
			},
		},
		{
			tag: "declaring a single audience using the Audience field",
			opts: &RawJWTOptions{
				TypeHeader:        "typeHeader",
				WithoutExpiration: true,
				Audience:          refString("tink-aud"),
			},
			expected: &RawJWT{
				typeHeader: "typeHeader",
				jsonpb: &spb.Struct{
					Fields: map[string]*spb.Value{
						"aud": spb.NewStringValue("tink-aud"),
					},
				},
			},
		},
	}
	for _, tc := range testCases {
		t.Run(tc.tag, func(t *testing.T) {
			rawJWT, err := NewRawJWT(tc.opts)
			if err != nil {
				t.Fatalf("generating valid RawJWT (%q): %v", tc.opts.ExpiresAt, err)
			}
			if diff := cmp.Diff(tc.expected, rawJWT, protocmp.Transform(), cmp.AllowUnexported(RawJWT{})); diff != "" {
				t.Fatalf("NewRawJWT(%v) returned unexpected diff (-want +got):\n%s", tc.opts, diff)
			}

		})
	}
}

func TestNewRawJWTValidationFailures(t *testing.T) {
	testCases := []newRawJWTTestCase{
		{
			tag: "empty RawJWTOptions options fails",
		},
		{
			tag: "no ExpiresAt specified and WithoutExpiration = false fails",
			opts: &RawJWTOptions{
				Audiences: []string{"tink-foo"},
			},
		},
		{
			tag: "ExpiresAt and WithoutExpiration = true fails",
			opts: &RawJWTOptions{
				Audiences:         []string{"tink-foo"},
				ExpiresAt:         refTime(validExpiration),
				WithoutExpiration: true,
			},
		},
		{
			tag: "specifying Audenience and Audiences fails",
			opts: &RawJWTOptions{
				Audiences:         []string{"tink-foo"},
				Audience:          refString("tink-bar"),
				WithoutExpiration: true,
			},
		},
		{
			tag: "empty audiences array fails",
			opts: &RawJWTOptions{
				ExpiresAt: refTime(validExpiration),
				Audiences: []string{},
			},
		},
		{
			tag: "audiences with invalid UTF-8 string fails",
			opts: &RawJWTOptions{
				WithoutExpiration: true,
				Audiences:         []string{"valid", invalidUTF8},
			},
		},
		{
			tag: "custom claims containing registered subject claims fails",
			opts: &RawJWTOptions{
				Audiences: []string{"tink-foo"},
				ExpiresAt: refTime(validExpiration),
				CustomClaims: map[string]interface{}{
					"sub": "overwrite",
				},
			},
		},
		{
			tag: "custom claims containing registered issuer claims fails",
			opts: &RawJWTOptions{
				Audiences: []string{"tink-foo"},
				ExpiresAt: refTime(validExpiration),
				CustomClaims: map[string]interface{}{
					"iss": "overwrite",
				},
			},
		},
		{
			tag: "custom claims containing registered jwt id claims fails",
			opts: &RawJWTOptions{
				Audiences: []string{"tink-foo"},
				ExpiresAt: refTime(validExpiration),
				CustomClaims: map[string]interface{}{
					"jti": "overwrite",
				},
			},
		},
		{
			tag: "custom claims containing registered expiration claims fails",
			opts: &RawJWTOptions{
				Audiences: []string{"tink-foo"},
				ExpiresAt: refTime(validExpiration),
				CustomClaims: map[string]interface{}{
					"exp": "overwrite",
				},
			},
		},
		{
			tag: "custom claims containing registered audience claims fails",
			opts: &RawJWTOptions{
				Audiences:         []string{"tink-foo"},
				WithoutExpiration: true,
				CustomClaims: map[string]interface{}{
					"aud": []interface{}{"overwrite"},
				},
			},
		},
		{
			tag: "custom claims with non standard JSON types fails",
			opts: &RawJWTOptions{
				Audiences: []string{"tink-foo"},
				ExpiresAt: refTime(validExpiration),
				CustomClaims: map[string]interface{}{
					"complex": time.Time{},
				},
			},
		},
		{
			tag: "non UTF-8 string on isser claim fails",
			opts: &RawJWTOptions{
				Audiences: []string{"tink-foo"},
				ExpiresAt: refTime(validExpiration),
				Issuer:    refString(invalidUTF8),
			},
		},
		{
			tag: "non UTF-8 string on subject claim fails",
			opts: &RawJWTOptions{
				Audiences:         []string{"tink-foo"},
				WithoutExpiration: true,
				Subject:           refString(invalidUTF8),
			},
		},
		{
			tag: "non UTF-8 string on JWT ID claim fails",
			opts: &RawJWTOptions{
				Audiences:         []string{"tink-foo"},
				WithoutExpiration: true,
				JWTID:             refString(invalidUTF8),
			},
		},
		{
			tag: "non UTF-8 string on custom claim fails",
			opts: &RawJWTOptions{
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
			opts: &RawJWTOptions{
				Audiences: []string{"tink-foo"},
				ExpiresAt: refTime(validExpiration),
				IssuedAt:  refTime(253402300800),
			},
		},
		{
			tag: "expires at timestamp greater than valid JWT max time fails",
			opts: &RawJWTOptions{
				Audiences: []string{"tink-foo"},
				ExpiresAt: refTime(253402300800),
			},
		},
		{
			tag: "not before timestamp smaller than valid JWT min time fails",
			opts: &RawJWTOptions{
				Audiences: []string{"tink-foo"},
				ExpiresAt: refTime(validExpiration),
				NotBefore: refTime(-5),
			},
		},
	}
	for _, tc := range testCases {
		t.Run(tc.tag, func(t *testing.T) {
			_, err := NewRawJWT(tc.opts)
			if err == nil {
				t.Errorf("expected error instead got nil")
			}
		})
	}
}

type jsonToJWTTestCase struct {
	tag      string
	json     string
	expected *RawJWT
}

func stringList(l []string) *spb.Value {
	vals := []*spb.Value{}
	for _, v := range l {
		vals = append(vals, spb.NewStringValue(v))
	}
	return spb.NewListValue(&spb.ListValue{Values: vals})
}

func TestFromJSON(t *testing.T) {
	testCases := []jsonToJWTTestCase{
		{
			tag: "registered claims",
			json: `{
				"aud": ["one", "two"],
				"iss": "tink-test",
				"exp": 457888
			}`,
			expected: &RawJWT{
				jsonpb: &spb.Struct{
					Fields: map[string]*spb.Value{
						"aud": stringList([]string{"one", "two"}),
						"iss": spb.NewStringValue("tink-test"),
						"exp": spb.NewNumberValue(457888),
					},
				},
			},
		},
		{
			tag: "all registered and custom claims",
			json: `{
				"aud": ["one", "two"],
				"iss": "tink-test",
				"sub": "subject",
				"exp": 457888,
				"nbf": 450888,
				"iat": 400888,
				"jti": "ss",
				"custom": {"arr": ["1", "2", "3"]}
			}`,
			expected: &RawJWT{
				jsonpb: &spb.Struct{
					Fields: map[string]*spb.Value{
						"aud":    stringList([]string{"one", "two"}),
						"iss":    spb.NewStringValue("tink-test"),
						"sub":    spb.NewStringValue("subject"),
						"exp":    spb.NewNumberValue(457888),
						"nbf":    spb.NewNumberValue(450888),
						"iat":    spb.NewNumberValue(400888),
						"jti":    spb.NewStringValue("ss"),
						"custom": spb.NewStructValue(&spb.Struct{Fields: map[string]*spb.Value{"arr": stringList([]string{"1", "2", "3"})}}),
					},
				},
			},
		},
		{
			tag:  "no claims present",
			json: "{}",
			expected: &RawJWT{
				jsonpb: &spb.Struct{
					Fields: map[string]*spb.Value{},
				},
			},
		},
		{
			tag:  "single string value audience present",
			json: `{"aud": "tink-aud"}`,
			expected: &RawJWT{
				jsonpb: &spb.Struct{
					Fields: map[string]*spb.Value{
						"aud": spb.NewStringValue("tink-aud"),
					},
				},
			},
		},
	}
	for _, tc := range testCases {
		t.Run(tc.tag, func(t *testing.T) {
			rawJWT, err := NewRawJWTFromJSON("", []byte(tc.json))
			if err != nil {
				t.Fatalf("parsing valid RawJWT: %v", err)
			}
			if diff := cmp.Diff(tc.expected, rawJWT, protocmp.Transform(), cmp.AllowUnexported(RawJWT{})); diff != "" {
				t.Fatalf("NewRawJWTFromJSON(%s) returned unexpected diff (-want +got):\n%s", tc.json, diff)
			}
		})
	}
}

func TestJSONPayload(t *testing.T) {
	opts := &RawJWTOptions{
		TypeHeader:        "typeHeader",
		WithoutExpiration: true,
		Subject:           refString("tink-subject"),
	}
	token, err := NewRawJWT(opts)
	if err != nil {
		t.Errorf("generating valid RawJWT: %v", err)
	}
	j, err := token.JSONPayload()
	if err != nil {
		t.Errorf("calling JSONPayload on rawJWT: %v", err)
	}
	expected := `{"sub":"tink-subject"}`
	if !cmp.Equal(string(j), expected) {
		t.Fatalf("JSONPayload output got %v, expected %v", string(j), expected)
	}

}

func TestFromJSONValidationFailures(t *testing.T) {
	testCases := []jsonToJWTTestCase{

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
			if _, err := NewRawJWTFromJSON("", []byte(tc.json)); err == nil {
				t.Errorf("expected error instead got nil")
			}
		})
	}
}
