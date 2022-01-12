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
