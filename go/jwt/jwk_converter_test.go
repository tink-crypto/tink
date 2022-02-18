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

package jwt_test

import (
	"bytes"
	"fmt"
	"testing"

	"google.golang.org/protobuf/proto"
	"github.com/google/tink/go/jwt"
	"github.com/google/tink/go/keyset"
	"github.com/google/tink/go/testkeyset"
	jepb "github.com/google/tink/go/proto/jwt_ecdsa_go_proto"
	tinkpb "github.com/google/tink/go/proto/tink_go_proto"
)

type jwkSetTestCase struct {
	tag           string
	jwkSet        string
	privateKeyset string
}

// syncronized with tests cases from JWK converter for C++
var jwkSetTestCases = []jwkSetTestCase{
	{
		tag: "ES256",
		jwkSet: `{
			"keys":[{
			"kty":"EC",
			"crv":"P-256",
			"x":"wO6uIxh8SkKOO8VjZXNRTteRcwCPE4_4JElKyaa0fcQ",
			"y":"7oRiYhnmkP6nqrdXWgtsWUWq5uFRLJkhyVFiWPRB278",
			"use":"sig","alg":"ES256","key_ops":["verify"],
			"kid":"EhuduQ"}]
		}`,
		privateKeyset: `{
				"primaryKeyId": 303799737,
				"key": [
				{
					"keyData": {
					"typeUrl": "type.googleapis.com/google.crypto.tink.JwtEcdsaPrivateKey",
					"value": "GiA2S/eedsXqu0DhnOlCJugsHugdpPaAGr/byxXXsZBiVRJGIiDuhGJiGeaQ/qeqt1daC2xZRarm4VEsmSHJUWJY9EHbvxogwO6uIxh8SkKOO8VjZXNRTteRcwCPE4/4JElKyaa0fcQQAQ==",
					"keyMaterialType": "ASYMMETRIC_PRIVATE"
					},
					"status": "ENABLED",
					"keyId": 303799737,
					"outputPrefixType": "TINK"
				}
			]
		}`,
	},
	{
		tag: "ES384",
		jwkSet: `{
			"keys":[{"kty":"EC","crv":"P-384",
			"x":"AEUCTkKhRDEgJ2pTiyPoSsIOERywrB2xjBDgUH8LLg0Ao9xT2SxKadxLdRFIr8Ll",
			"y":"wQcqkI9pV66PJFmJVyZ7BsqvFaqoWT-jAFvYNjsgdvAIpyB3MHWXkxNhlPYcpEIf",
			"use":"sig","alg":"ES384","key_ops":["verify"],"kid":"f-fUcw"}]
		}`,
		privateKeyset: `{
			"primaryKeyId": 2145899635,
			"key": [
				{
					"keyData": {
						"typeUrl": "type.googleapis.com/google.crypto.tink.JwtEcdsaPrivateKey",
						"value": "GjCfHcFYHsiwTcBCATSyjOyJ64iy4LGa4OuFaR9wZqkYTuYrY1I3ssxO4UK11j/IUe4SZiIwwQcqkI9pV66PJFmJVyZ7BsqvFaqoWT+jAFvYNjsgdvAIpyB3MHWXkxNhlPYcpEIfGjAARQJOQqFEMSAnalOLI+hKwg4RHLCsHbGMEOBQfwsuDQCj3FPZLEpp3Et1EUivwuUQAg==",
						"keyMaterialType": "ASYMMETRIC_PRIVATE"
					},
					"status": "ENABLED",
					"keyId": 2145899635,
					"outputPrefixType": "TINK"
				}
			]
		}`,
	},
	{
		tag: "ES512",
		jwkSet: `{
			"keys":[{"kty":"EC","crv":"P-521",
			"x":"AKRFrHHoTaFAO-d4sCOw78KyUlZijBgqfp2rXtkLZ_QQGLtDM2nScAilkryvw3c_4fM39CEygtSunFLI9xyUyE3m",
			"y":"ANZK5JjTcNAKtezmXFvDSkrxdxPiuX2uPq6oR3M0pb2wqnfDL-nWeWcKb2nAOxYSyydsrZ98bxBL60lEr20x1Gc_",
			"use":"sig","alg":"ES512","key_ops":["verify"],"kid":"WDqzeQ"}]
		}`,
		privateKeyset: `{
			"primaryKeyId": 1480242041,
			"key": [
				{
					"keyData": {
						"typeUrl": "type.googleapis.com/google.crypto.tink.JwtEcdsaPrivateKey",
						"value": "GkIBnhWq6UrOj8hKwGovjSsLT+dtAGlRqoIkQ2FzMeKxIApx0dT3O4yHrmi6v5sElZHM6BsLz47IopAOajVRYGh48b0SigEiQgDWSuSY03DQCrXs5lxbw0pK8XcT4rl9rj6uqEdzNKW9sKp3wy/p1nlnCm9pwDsWEssnbK2ffG8QS+tJRK9tMdRnPxpCAKRFrHHoTaFAO+d4sCOw78KyUlZijBgqfp2rXtkLZ/QQGLtDM2nScAilkryvw3c/4fM39CEygtSunFLI9xyUyE3mEAM=",
						"keyMaterialType": "ASYMMETRIC_PRIVATE"
					},
					"status": "ENABLED",
					"keyId": 1480242041,
					"outputPrefixType": "TINK"
				}
			]
		}`,
	},
	{
		tag: "ES256_NO_KID",
		jwkSet: `{
			"keys":[{
			"kty":"EC",
			"crv":"P-256",
			"x":"ytH8MlvqTx3X-eL0pdx4ULKUb2YOi2DPnIPpSaIk28M",
			"y":"AO5TMe5lNcjJpuGjjGtHd4gX9POG9dh_vG-8ptp7HJs",
			"use":"sig","alg":"ES256","key_ops":["verify"]}]
		}`,
		privateKeyset: `{
			"primaryKeyId": 765975903,
			"key": [
				{
					"keyData": {
						"typeUrl": "type.googleapis.com/google.crypto.tink.JwtEcdsaPrivateKey",
						"value": "GiCbUAItoAVleOSwYdPWs563CCFhGHSdX4t/C2xBY2J/ERJGIiAA7lMx7mU1yMmm4aOMa0d3iBf084b12H+8b7ym2nscmxogytH8MlvqTx3X+eL0pdx4ULKUb2YOi2DPnIPpSaIk28MQAQ==",
						"keyMaterialType": "ASYMMETRIC_PRIVATE"
					},
					"status": "ENABLED",
					"keyId": 765975903,
					"outputPrefixType": "RAW"
				}
			]
		}`,
	},
}

// TODO(b/202065153): Test To KeysetHandle and back to JWT set.
// TODO(b/202065153): Test case with multiple keysets.
func TestToPublicKeysetHandle(t *testing.T) {
	for _, tc := range jwkSetTestCases {
		t.Run(tc.tag, func(t *testing.T) {
			if _, err := jwt.JWKSetToPublicKeysetHandle([]byte(tc.jwkSet)); err != nil {
				t.Errorf("jwt.JWKSetToPublicKeysetHandle() err = %v, want nil", err)
			}
		})
	}
}

func createKeysetHandle(key string) (*keyset.Handle, error) {
	ks, err := keyset.NewJSONReader(bytes.NewReader([]byte(key))).Read()
	if err != nil {
		return nil, fmt.Errorf("keyset.NewJSONReader().Read() err = %v, want nil", err)
	}
	return testkeyset.NewHandle(ks)
}

func TestJWKSetToPublicKeysetHandleVerifyValidJWT(t *testing.T) {
	rawJWT, err := jwt.NewRawJWT(&jwt.RawJWTOptions{WithoutExpiration: true})
	if err != nil {
		t.Fatalf("jwt.NewRawJWT() err = %v, want nil", err)
	}
	validator, err := jwt.NewValidator(&jwt.ValidatorOpts{AllowMissingExpiration: true})
	if err != nil {
		t.Fatalf("jwt.NewValidator() err = %v, want nil", err)
	}
	for _, tc := range jwkSetTestCases {
		t.Run(tc.tag, func(t *testing.T) {
			privateHandle, err := createKeysetHandle(tc.privateKeyset)
			if err != nil {
				t.Fatalf("createKeysetHandle() err = %v, want nil", err)
			}
			signer, err := jwt.NewSigner(privateHandle)
			if err != nil {
				t.Fatalf("jwt.NewSigner() err = %v, want nil", err)
			}
			compact, err := signer.SignAndEncode(rawJWT)
			if err != nil {
				t.Fatalf("signer.SignAndEncode() err = %v, want nil", err)
			}
			pubHandle, err := jwt.JWKSetToPublicKeysetHandle([]byte(tc.jwkSet))
			if err != nil {
				t.Fatalf("jwt.JWKSetToPublicKeysetHandle() err = %v, want nil", err)
			}
			verifier, err := jwt.NewVerifier(pubHandle)
			if err != nil {
				t.Fatalf("jwt.NewVerifier() err = %v, want nil", err)
			}
			if _, err := verifier.VerifyAndDecode(compact, validator); err != nil {
				t.Errorf("verifier.VerifyAndDecode() err = %v, want nil", err)
			}
		})
	}
}

func TestJWKSetToPublicKeysetHandleInvalidJSONFails(t *testing.T) {
	if _, err := jwt.JWKSetToPublicKeysetHandle([]byte(`({[}])`)); err == nil {
		t.Errorf("jwt.JWKSetToPublicKeysetHandle() err = nil, want error")
	}
}

func TestJWKSetToPublicKeysetES256WithSmallXFails(t *testing.T) {
	jwk := `{
    "keys":[{
    "kty":"EC",
    "crv":"P-256",
    "x":"wO6uIxh8Sk",
    "y":"7oRiYhnmkP6nqrdXWgtsWUWq5uFRLJkhyVFiWPRB278",
    "use":"sig","alg":"ES256","key_ops":["verify"]}],
    "kid":"EhuduQ"
  }`
	// Keys in the keyset are validated when the primitive is generated.
	// JWKSetToPublicKeysetHandle but NewVerifier will fail.
	pubHandle, err := jwt.JWKSetToPublicKeysetHandle([]byte(jwk))
	if err != nil {
		t.Fatalf("jwt.JWKSetToPublicKeysetHandle() err = %v, want nil", err)
	}
	if _, err := jwt.NewVerifier(pubHandle); err == nil {
		t.Errorf("jwt.NewVerifier() err = nil, want error")
	}
}

func TestJWKSetToPublicKeysetES256WithSmallYFails(t *testing.T) {
	jwk := `{
    "keys":[{
    "kty":"EC",
    "crv":"P-256",
    "x":"wO6uIxh8SkKOO8VjZXNRTteRcwCPE4_4JElKyaa0fcQ",
    "y":"7oRiYhnmkP6nqrdXWgtsWUWq5uFRLJkhyVFiWPRB27",
    "use":"sig","alg":"ES256","key_ops":["verify"]}],
    "kid":"EhuduQ"
  }`
	// Keys in the keyset are validated when the primitive is generated.
	// JWKSetToPublicKeysetHandle but NewVerifier will fail.
	pubHandle, err := jwt.JWKSetToPublicKeysetHandle([]byte(jwk))
	if err != nil {
		t.Fatalf("jwt.JWKSetToPublicKeysetHandle() err = %v, want nil", err)
	}
	if _, err := jwt.NewVerifier(pubHandle); err == nil {
		t.Errorf("jwt.NewVerifier() err = nil, want error")
	}
}

func TestJWKSetToPublicKeysetES256CorrectlySetsKID(t *testing.T) {
	jwk := `{
    "keys":[{
    "kty":"EC",
    "crv":"P-256",
    "x":"wO6uIxh8SkKOO8VjZXNRTteRcwCPE4_4JElKyaa0fcQ",
    "y":"7oRiYhnmkP6nqrdXWgtsWUWq5uFRLJkhyVFiWPRB278",
    "use":"sig","alg":"ES256","key_ops":["verify"],
    "kid":"EhuduQ"}]
  }`
	pubHandle, err := jwt.JWKSetToPublicKeysetHandle([]byte(jwk))
	if err != nil {
		t.Fatalf("jwt.JWKSetToPublicKeysetHandle() err = %v, want nil", err)
	}
	ks := testkeyset.KeysetMaterial(pubHandle)

	if len(ks.GetKey()) != 1 {
		t.Errorf("len(ks.GetKey()) got %d keys, want 1", len(ks.GetKey()))
	}
	key := ks.GetKey()[0]
	if key.GetOutputPrefixType() != tinkpb.OutputPrefixType_RAW {
		t.Errorf("key.GetOutputPrefixType() got %q, want %q", key.GetOutputPrefixType(), tinkpb.OutputPrefixType_RAW)
	}
	if key.GetKeyData() == nil {
		t.Fatalf("invalid key")
	}
	pubKey := &jepb.JwtEcdsaPublicKey{}
	if err := proto.Unmarshal(key.GetKeyData().GetValue(), pubKey); err != nil {
		t.Fatalf("proto.Unmarshal(key.GetKeyData(), pubKey) err = %v, want nil", err)
	}
	if pubKey.GetCustomKid().GetValue() != "EhuduQ" {
		t.Errorf("key.GetCustomKid() got %q, want EhuduQ", pubKey.GetCustomKid())
	}
}

func TestJWKSetToPublicKeysetES256WithoutOptionalFieldsSucceeds(t *testing.T) {
	jwk := `{
    "keys":[{
    "kty":"EC",
    "crv":"P-256",
    "x":"wO6uIxh8SkKOO8VjZXNRTteRcwCPE4_4JElKyaa0fcQ",
    "y":"7oRiYhnmkP6nqrdXWgtsWUWq5uFRLJkhyVFiWPRB278",
    "alg":"ES256"}]
  }`
	if _, err := jwt.JWKSetToPublicKeysetHandle([]byte(jwk)); err != nil {
		t.Fatalf("jwt.JWKSetToPublicKeysetHandle() err = %v, want nil", err)
	}
}

func TestJWKSetToPublicKeysetInvalidES256PublicKeys(t *testing.T) {
	for _, tc := range []jwkSetTestCase{
		{
			tag:    "jwk set is not a json",
			jwkSet: `5`,
		},
		{
			tag:    "empty jwk set",
			jwkSet: `{}`,
		},
		{
			tag:    "no keys in jwk set",
			jwkSet: `{"keys": []}`,
		},
		{
			tag:    "keys of wrong type in jwk set",
			jwkSet: `{"keys": "value"}`,
		},
		{
			tag:    "keys not a json object",
			jwkSet: `{"keys":[1]}`,
		},
		{
			tag: "without kty",
			jwkSet: `{
				"keys":[{
				"crv":"P-256",
				"x":"wO6uIxh8SkKOO8VjZXNRTteRcwCPE4_4JElKyaa0fcQ",
				"y":"7oRiYhnmkP6nqrdXWgtsWUWq5uFRLJkhyVFiWPRB278",
				"use":"sig","alg":"ES256","key_ops":["verify"],
				"kid":"EhuduQ"}]
			}`,
		},
		{
			tag: "without algorithm",
			jwkSet: `{
				"keys":[{
				"kty":"EC",
				"crv":"P-256",
				"x":"wO6uIxh8SkKOO8VjZXNRTteRcwCPE4_4JElKyaa0fcQ",
				"y":"7oRiYhnmkP6nqrdXWgtsWUWq5uFRLJkhyVFiWPRB278",
				"use":"sig","key_ops":["verify"],
				"kid":"EhuduQ"}]
			}`,
		},
		{
			tag: "empty algorithm",
			jwkSet: `{
				"keys":[{
				"kty":"EC",
				"crv":"P-256",
				"x":"wO6uIxh8SkKOO8VjZXNRTteRcwCPE4_4JElKyaa0fcQ",
				"y":"7oRiYhnmkP6nqrdXWgtsWUWq5uFRLJkhyVFiWPRB278",
				"use":"sig", "alg":"", "key_ops":["verify"],
				"kid":"EhuduQ"}]
			}`,
		},
		{
			tag: "invalid algorthm prefix",
			jwkSet: `{
				"keys":[{
				"kty":"EC",
				"crv":"P-256",
				"x":"wO6uIxh8SkKOO8VjZXNRTteRcwCPE4_4JElKyaa0fcQ",
				"y":"7oRiYhnmkP6nqrdXWgtsWUWq5uFRLJkhyVFiWPRB278",
				"use":"sig", "alg":"SS256", "key_ops":["verify"],
				"kid":"EhuduQ"}]
			}`,
		},
		{
			tag: "invalid algorithm",
			jwkSet: `{
				"keys":[{
				"kty":"EC",
				"crv":"P-256",
				"x":"wO6uIxh8SkKOO8VjZXNRTteRcwCPE4_4JElKyaa0fcQ",
				"y":"7oRiYhnmkP6nqrdXWgtsWUWq5uFRLJkhyVFiWPRB278",
				"use":"sig","alg":"ES257","key_ops":["verify"],
				"kid":"EhuduQ"}]
			}`,
		},
		{
			tag: "algorithm not a string",
			jwkSet: `{
				"keys":[{
				"kty":"EC",
				"crv":"P-256",
				"x":"wO6uIxh8SkKOO8VjZXNRTteRcwCPE4_4JElKyaa0fcQ",
				"y":"7oRiYhnmkP6nqrdXWgtsWUWq5uFRLJkhyVFiWPRB278",
				"use":"sig","alg":256,"key_ops":["verify"],
				"kid":"EhuduQ"}]
			}`,
		},
		{
			tag: "invalid curve and algorithm",
			jwkSet: `{
				"keys":[{
				"kty":"EC",
				"crv":"P-384",
				"x":"wO6uIxh8SkKOO8VjZXNRTteRcwCPE4_4JElKyaa0fcQ",
				"y":"7oRiYhnmkP6nqrdXWgtsWUWq5uFRLJkhyVFiWPRB278",
				"use":"sig","alg":"ES512","key_ops":["verify"],
				"kid":"EhuduQ"}]
			}`,
		},
		{
			tag: "without curve",
			jwkSet: `{
				"keys":[{
				"kty":"EC",
				"x":"wO6uIxh8SkKOO8VjZXNRTteRcwCPE4_4JElKyaa0fcQ",
				"y":"7oRiYhnmkP6nqrdXWgtsWUWq5uFRLJkhyVFiWPRB278",
				"use":"sig","alg":"ES512","key_ops":["verify"],
				"kid":"EhuduQ"}]
			}`,
		},
		{
			tag: "invalid key ops",
			jwkSet: `{
				"keys":[{
				"kty":"EC",
				"crv":"P-256",
				"x":"wO6uIxh8SkKOO8VjZXNRTteRcwCPE4_4JElKyaa0fcQ",
				"y":"7oRiYhnmkP6nqrdXWgtsWUWq5uFRLJkhyVFiWPRB278",
				"use":"sig","alg":"ES256","key_ops":["verify "],
				"kid":"EhuduQ"}]
			}`,
		},
		{
			tag: "multiple key ops",
			jwkSet: `{
				"keys":[{
				"kty":"EC",
				"crv":"P-256",
				"x":"wO6uIxh8SkKOO8VjZXNRTteRcwCPE4_4JElKyaa0fcQ",
				"y":"7oRiYhnmkP6nqrdXWgtsWUWq5uFRLJkhyVFiWPRB278",
				"use":"sig","alg":"ES256","key_ops":["verify", "sign"],
				"kid":"EhuduQ"}]
			}`,
		},
		{
			tag: "invalid key ops type",
			jwkSet: `{
				"keys":[{
				"kty":"EC",
				"crv":"P-256",
				"x":"wO6uIxh8SkKOO8VjZXNRTteRcwCPE4_4JElKyaa0fcQ",
				"y":"7oRiYhnmkP6nqrdXWgtsWUWq5uFRLJkhyVFiWPRB278",
				"use":"sig","alg":"ES256","key_ops":"verify",
				"kid":"EhuduQ"}]
			}`,
		},
		{
			tag: "invalid key ops type inside list",
			jwkSet: `{
				"keys":[{
				"kty":"EC",
				"crv":"P-256",
				"x":"wO6uIxh8SkKOO8VjZXNRTteRcwCPE4_4JElKyaa0fcQ",
				"y":"7oRiYhnmkP6nqrdXWgtsWUWq5uFRLJkhyVFiWPRB278",
				"use":"sig","alg":"ES256","key_ops":[1],
				"kid":"EhuduQ"}]
			}`,
		},
		{
			tag: "invalid use",
			jwkSet: `{
				"keys":[{
				"kty":"EC",
				"crv":"P-256",
				"x":"wO6uIxh8SkKOO8VjZXNRTteRcwCPE4_4JElKyaa0fcQ",
				"y":"7oRiYhnmkP6nqrdXWgtsWUWq5uFRLJkhyVFiWPRB278",
				"use":"zag","alg":"ES256","key_ops":["verify"],
				"kid":"EhuduQ"}]
			}`,
		},
		{
			tag: "without x coordinate",
			jwkSet: `{
				"keys":[{
				"kty":"EC",
				"crv":"P-256",
				"y":"7oRiYhnmkP6nqrdXWgtsWUWq5uFRLJkhyVFiWPRB278",
				"use":"sig","alg":"ES256","key_ops":["verify"],
				"kid":"EhuduQ"}]
			}`,
		},
		{
			tag: "without y coordinate",
			jwkSet: `{
				"keys":[{
				"kty":"EC",
				"crv":"P-256",
				"x":"wO6uIxh8SkKOO8VjZXNRTteRcwCPE4_4JElKyaa0fcQ",
				"use":"sig","alg":"ES256","key_ops":["verify"],
				"kid":"EhuduQ"}]
			}`,
		},
		{
			tag: "kid of invalid type",
			jwkSet: `{
			"keys":[{
			"kty":"EC",
			"crv":"P-256",
			"x":"wO6uIxh8SkKOO8VjZXNRTteRcwCPE4_4JElKyaa0fcQ",
			"y":"7oRiYhnmkP6nqrdXWgtsWUWq5uFRLJkhyVFiWPRB278",
			"use":"sig","alg":"ES256","key_ops":["verify"],
			"kid":5}]
			}`,
		},
		{
			tag: "with private key",
			jwkSet: `{
				"keys":[{
				"kty":"EC",
				"crv":"P-256",
				"alg":"ES256",
				"x":"SVqB4JcUD6lsfvqMr-OKUNUphdNn64Eay60978ZlL74",
				"y":"lf0u0pMj4lGAzZix5u4Cm5CMQIgMNpkwy163wtKYVKI",
				"d":"0g5vAEKzugrXaRbgKG0Tj2qJ5lMP4Bezds1_sTybkfk"
				}]
			}`,
		},
	} {
		t.Run(tc.tag, func(t *testing.T) {
			if _, err := jwt.JWKSetToPublicKeysetHandle([]byte(tc.jwkSet)); err == nil {
				t.Fatalf("jwt.JWKSetToPublicKeysetHandle() err = nil, want error")
			}
		})
	}
}
