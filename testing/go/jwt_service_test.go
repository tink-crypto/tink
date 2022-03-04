// Copyright 2022 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
///////////////////////////////////////////////////////////////////////////////

package services_test

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/google/go-cmp/cmp"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/testing/protocmp"
	"github.com/google/tink/go/aead"
	"github.com/google/tink/go/jwt"
	pb "github.com/google/tink/proto/testing/testing_api_go_grpc"
	"github.com/google/tink/testing/go/services"
)

func verifiedJWTFromResponse(response *pb.JwtVerifyResponse) (*pb.JwtToken, error) {
	switch r := response.Result.(type) {
	case *pb.JwtVerifyResponse_VerifiedJwt:
		return r.VerifiedJwt, nil
	case *pb.JwtVerifyResponse_Err:
		return nil, errors.New(r.Err)
	default:
		return nil, fmt.Errorf("response.Result has unexpected type %T", r)
	}
}

func signedCompactJWTFromResponse(response *pb.JwtSignResponse) (string, error) {
	switch r := response.Result.(type) {
	case *pb.JwtSignResponse_SignedCompactJwt:
		return r.SignedCompactJwt, nil
	case *pb.JwtSignResponse_Err:
		return "", errors.New(r.Err)
	default:
		return "", fmt.Errorf("response.Result has unexpected type %T", r)
	}
}

type jwtTestCase struct {
	tag       string
	rawJWT    *pb.JwtToken
	validator *pb.JwtValidator
}

func TestJWTComputeInvalidJWT(t *testing.T) {
	for _, tc := range []jwtTestCase{
		{
			tag:    "nil rawJWT",
			rawJWT: nil,
		},
		{
			tag: "invalid json array string",
			rawJWT: &pb.JwtToken{
				CustomClaims: map[string]*pb.JwtClaimValue{
					"cc-array": &pb.JwtClaimValue{Kind: &pb.JwtClaimValue_JsonArrayValue{JsonArrayValue: "{35}"}},
				},
			},
		},
		{
			tag: "invalid json object string",
			rawJWT: &pb.JwtToken{
				CustomClaims: map[string]*pb.JwtClaimValue{
					"cc-object": &pb.JwtClaimValue{Kind: &pb.JwtClaimValue_JsonObjectValue{JsonObjectValue: `["o":"a"]`}},
				},
			},
		},
	} {
		t.Run(tc.tag, func(t *testing.T) {
			keysetService := &services.KeysetService{}
			jwtService := &services.JWTService{}
			ctx := context.Background()
			template, err := proto.Marshal(jwt.HS256Template())
			if err != nil {
				t.Fatalf("proto.Marshal(jwt.HS256Template()) failed: %v", err)
			}
			keyset, err := genKeyset(ctx, keysetService, template)
			if err != nil {
				t.Fatalf("genKeyset failed: %v", err)
			}
			signResponse, err := jwtService.ComputeMacAndEncode(ctx, &pb.JwtSignRequest{Keyset: keyset, RawJwt: tc.rawJWT})
			if err != nil {
				t.Fatalf("jwtService.ComputeMacAndEncode() err = %v, want nil", err)
			}
			if _, err := signedCompactJWTFromResponse(signResponse); err == nil {
				t.Fatalf("JwtSignResponse: error = nil, want error")
			}
		})
	}
}

func TestJWTComputeMACWithInvalidKeysetFails(t *testing.T) {
	keysetService := &services.KeysetService{}
	jwtService := &services.JWTService{}
	ctx := context.Background()
	template, err := proto.Marshal(aead.AES256GCMKeyTemplate())
	if err != nil {
		t.Fatalf("proto.Marshal(jwt.AES256GCMKeyTemplate()) failed: %v", err)
	}
	keyset, err := genKeyset(ctx, keysetService, template)
	if err != nil {
		t.Fatalf("genKeyset failed: %v", err)
	}
	rawJWT := &pb.JwtToken{
		TypeHeader: &pb.StringValue{Value: "JWT"},
		Issuer:     &pb.StringValue{Value: "issuer"},
	}
	signResponse, err := jwtService.ComputeMacAndEncode(ctx, &pb.JwtSignRequest{Keyset: keyset, RawJwt: rawJWT})
	if err != nil {
		t.Fatalf("jwtService.ComputeMacAndEncode() err = %v, want nil", err)
	}
	if _, err := signedCompactJWTFromResponse(signResponse); err == nil {
		t.Fatalf("JwtSignResponse: error = nil, want error")
	}
}

func TestJWTComputeAndVerifyMac(t *testing.T) {
	for _, tc := range []jwtTestCase{
		{
			tag: "all claims and custom claims",
			rawJWT: &pb.JwtToken{
				TypeHeader: &pb.StringValue{Value: "JWT"},
				Issuer:     &pb.StringValue{Value: "issuer"},
				Subject:    &pb.StringValue{Value: "subject"},
				JwtId:      &pb.StringValue{Value: "tink"},
				Audiences:  []string{"audience"},
				Expiration: &pb.Timestamp{Seconds: 123456},
				NotBefore:  &pb.Timestamp{Seconds: 12345},
				IssuedAt:   &pb.Timestamp{Seconds: 1234},
				CustomClaims: map[string]*pb.JwtClaimValue{
					"cc-null":   &pb.JwtClaimValue{Kind: &pb.JwtClaimValue_NullValue{}},
					"cc-num":    &pb.JwtClaimValue{Kind: &pb.JwtClaimValue_NumberValue{NumberValue: 5.67}},
					"cc-bool":   &pb.JwtClaimValue{Kind: &pb.JwtClaimValue_BoolValue{BoolValue: true}},
					"cc-string": &pb.JwtClaimValue{Kind: &pb.JwtClaimValue_StringValue{StringValue: "foo bar"}},
					"cc-array":  &pb.JwtClaimValue{Kind: &pb.JwtClaimValue_JsonArrayValue{JsonArrayValue: "[35]"}},
					"cc-object": &pb.JwtClaimValue{Kind: &pb.JwtClaimValue_JsonObjectValue{JsonObjectValue: `{"key":"val"}`}},
				},
			},
			validator: &pb.JwtValidator{
				ExpectedTypeHeader: &pb.StringValue{Value: "JWT"},
				ExpectedIssuer:     &pb.StringValue{Value: "issuer"},
				ExpectedAudience:   &pb.StringValue{Value: "audience"},
				Now:                &pb.Timestamp{Seconds: 12345},
				ClockSkew:          &pb.Duration{Seconds: 0},
			},
		},
		{
			tag: "without custom claims",
			rawJWT: &pb.JwtToken{
				TypeHeader: &pb.StringValue{Value: "JWT"},
				Issuer:     &pb.StringValue{Value: "issuer"},
				Subject:    &pb.StringValue{Value: "subject"},
				Audiences:  []string{"audience"},
			},
			validator: &pb.JwtValidator{
				ExpectedTypeHeader:     &pb.StringValue{Value: "JWT"},
				ExpectedIssuer:         &pb.StringValue{Value: "issuer"},
				ExpectedAudience:       &pb.StringValue{Value: "audience"},
				AllowMissingExpiration: true,
			},
		},
		{
			tag: "without expiration",
			rawJWT: &pb.JwtToken{
				Subject: &pb.StringValue{Value: "subject"},
			},
			validator: &pb.JwtValidator{
				AllowMissingExpiration: true,
			},
		},
		{
			tag: "clock skew",
			rawJWT: &pb.JwtToken{
				Expiration: &pb.Timestamp{Seconds: 1234},
			},
			validator: &pb.JwtValidator{
				Now:       &pb.Timestamp{Seconds: 1235},
				ClockSkew: &pb.Duration{Seconds: 2},
			},
		},
	} {
		t.Run(tc.tag, func(t *testing.T) {
			keysetService := &services.KeysetService{}
			jwtService := &services.JWTService{}
			ctx := context.Background()
			template, err := proto.Marshal(jwt.HS256Template())
			if err != nil {
				t.Fatalf("proto.Marshal(jwt.HS256Template()) failed: %v", err)
			}
			keyset, err := genKeyset(ctx, keysetService, template)
			if err != nil {
				t.Fatalf("genKeyset failed: %v", err)
			}

			signResponse, err := jwtService.ComputeMacAndEncode(ctx, &pb.JwtSignRequest{Keyset: keyset, RawJwt: tc.rawJWT})
			if err != nil {
				t.Fatalf("jwtService.ComputeMacAndEncode() err = %v, want nil", err)
			}
			compact, err := signedCompactJWTFromResponse(signResponse)
			if err != nil {
				t.Fatalf("JwtSignResponse_Err: %v", err)
			}
			verifyResponse, err := jwtService.VerifyMacAndDecode(ctx, &pb.JwtVerifyRequest{Keyset: keyset, SignedCompactJwt: compact, Validator: tc.validator})
			if err != nil {
				t.Fatalf("jwtService.VerifyMacAndDecode() err = %v, want nil", err)
			}
			verifiedJWT, err := verifiedJWTFromResponse(verifyResponse)
			if err != nil {
				t.Fatalf("JwtVerifyResponse_Err: %v", err)
			}
			if !cmp.Equal(verifiedJWT, tc.rawJWT, protocmp.Transform()) {
				t.Errorf("verifiedJWT doesn't match expected value: (+ got, - want) %v", cmp.Diff(verifiedJWT, tc.rawJWT, protocmp.Transform()))
			}
		})
	}
}

func TestJWTVerifyMACFailures(t *testing.T) {
	keysetService := &services.KeysetService{}
	jwtService := &services.JWTService{}
	ctx := context.Background()
	template, err := proto.Marshal(jwt.HS256Template())
	if err != nil {
		t.Fatalf("proto.Marshal(jwt.HS256Template()) failed: %v", err)
	}
	keyset, err := genKeyset(ctx, keysetService, template)
	if err != nil {
		t.Fatalf("genKeyset failed: %v", err)
	}
	rawJWT := &pb.JwtToken{
		TypeHeader: &pb.StringValue{Value: "JWT"},
		Expiration: &pb.Timestamp{Seconds: 123456},
		NotBefore:  &pb.Timestamp{Seconds: 12345},
		IssuedAt:   &pb.Timestamp{Seconds: 1234},
	}
	signResponse, err := jwtService.ComputeMacAndEncode(ctx, &pb.JwtSignRequest{Keyset: keyset, RawJwt: rawJWT})
	if err != nil {
		t.Fatalf("jwtService.ComputeMacAndEncode() err = %v, want nil", err)
	}
	compact, err := signedCompactJWTFromResponse(signResponse)
	if err != nil {
		t.Fatalf("JwtSignResponse_Err: %v", err)
	}
	validator := &pb.JwtValidator{
		ExpectedTypeHeader: &pb.StringValue{Value: "JWT"},
		Now:                &pb.Timestamp{Seconds: 12345},
	}
	verifyResponse, err := jwtService.VerifyMacAndDecode(ctx, &pb.JwtVerifyRequest{Keyset: keyset, SignedCompactJwt: compact, Validator: validator})
	if err != nil {
		t.Fatalf("jwtService.VerifyMacAndDecode() err = %v, want nil", err)
	}
	if _, err := verifiedJWTFromResponse(verifyResponse); err != nil {
		t.Fatalf("JwtVerifyResponse_Err: %v", err)
	}
	for _, tc := range []jwtTestCase{
		{
			tag: "unexpected type header",
			validator: &pb.JwtValidator{
				ExpectedTypeHeader: &pb.StringValue{Value: "unexpected"},
				Now:                &pb.Timestamp{Seconds: 12345},
			},
		},
		{
			tag: "expired token",
			validator: &pb.JwtValidator{
				ExpectedTypeHeader: &pb.StringValue{Value: "JWT"},
				Now:                &pb.Timestamp{Seconds: 999999999999},
			},
		},
		{
			tag: "expect issued in the past",
			validator: &pb.JwtValidator{
				ExpectedTypeHeader:    &pb.StringValue{Value: "JWT"},
				Now:                   &pb.Timestamp{Seconds: 1233},
				ExpectIssuedInThePast: true,
			},
		},
	} {
		t.Run(tc.tag, func(t *testing.T) {
			verifyResponse, err := jwtService.VerifyMacAndDecode(ctx, &pb.JwtVerifyRequest{Keyset: keyset, SignedCompactJwt: compact, Validator: tc.validator})
			if err != nil {
				t.Fatalf("jwtService.VerifyMacAndDecode() err = %v, want nil", err)
			}
			if _, err := verifiedJWTFromResponse(verifyResponse); err == nil {
				t.Fatalf("JwtVerifyResponse_Err: nil, want error")
			}
		})
	}
}

func TestJWTPublicKeySignWithInvalidKeysetFails(t *testing.T) {
	keysetService := &services.KeysetService{}
	jwtService := &services.JWTService{}

	ctx := context.Background()
	template, err := proto.Marshal(aead.AES256GCMKeyTemplate())
	if err != nil {
		t.Fatalf("proto.Marshal(aead.AES256GCMKeyTemplate()) failed: %v", err)
	}
	privateKeyset, err := genKeyset(ctx, keysetService, template)
	if err != nil {
		t.Fatalf("genKeyset failed: %v", err)
	}
	rawJWT := &pb.JwtToken{
		Subject: &pb.StringValue{Value: "tink-subject"},
	}
	signResponse, err := jwtService.PublicKeySignAndEncode(ctx, &pb.JwtSignRequest{Keyset: privateKeyset, RawJwt: rawJWT})
	if err != nil {
		t.Fatalf("jwtService.PublicKeySignAndEncode() err = %v", err)
	}
	if _, err := signedCompactJWTFromResponse(signResponse); err == nil {
		t.Fatalf("JwtSignResponse_Err: nil want error")
	}
}

func TestJWTPublicKeySignInvalidTokenFails(t *testing.T) {
	keysetService := &services.KeysetService{}
	jwtService := &services.JWTService{}

	ctx := context.Background()
	template, err := proto.Marshal(jwt.ES256Template())
	if err != nil {
		t.Fatalf("proto.Marshal(jwt.ES256Template()) failed: %v", err)
	}
	privateKeyset, err := genKeyset(ctx, keysetService, template)
	if err != nil {
		t.Fatalf("genKeyset failed: %v", err)
	}
	for _, tc := range []jwtTestCase{
		{
			tag:    "nil rawJWT",
			rawJWT: nil,
		},
		{
			tag: "invalid json array string",
			rawJWT: &pb.JwtToken{
				CustomClaims: map[string]*pb.JwtClaimValue{
					"cc-array": &pb.JwtClaimValue{Kind: &pb.JwtClaimValue_JsonArrayValue{JsonArrayValue: "{35}"}},
				},
			},
		},
		{
			tag: "invalid json object string",
			rawJWT: &pb.JwtToken{
				CustomClaims: map[string]*pb.JwtClaimValue{
					"cc-object": &pb.JwtClaimValue{Kind: &pb.JwtClaimValue_JsonObjectValue{JsonObjectValue: `["o":"a"]`}},
				},
			},
		},
	} {
		t.Run(tc.tag, func(t *testing.T) {
			signResponse, err := jwtService.PublicKeySignAndEncode(ctx, &pb.JwtSignRequest{Keyset: privateKeyset, RawJwt: tc.rawJWT})
			if err != nil {
				t.Fatalf("jwtService.PublicKeySignAndEncode() err = %v", err)
			}
			if _, err := signedCompactJWTFromResponse(signResponse); err == nil {
				t.Fatalf("JwtSignResponse_Err: nil want error")
			}
		})
	}
}

func TestJWTPublicKeyVerifyFails(t *testing.T) {
	keysetService := &services.KeysetService{}
	jwtService := &services.JWTService{}

	ctx := context.Background()
	template, err := proto.Marshal(jwt.ES256Template())
	if err != nil {
		t.Fatalf("proto.Marshal(jwt.ES256Template()) failed: %v", err)
	}
	privateKeyset, err := genKeyset(ctx, keysetService, template)
	if err != nil {
		t.Fatalf("genKeyset failed: %v", err)
	}
	publicKeyset, err := pubKeyset(ctx, keysetService, privateKeyset)
	if err != nil {
		t.Fatalf("pubKeyset failed: %v", err)
	}
	rawJWT := &pb.JwtToken{
		Subject: &pb.StringValue{Value: "tink-subject"},
	}
	signResponse, err := jwtService.PublicKeySignAndEncode(ctx, &pb.JwtSignRequest{Keyset: privateKeyset, RawJwt: rawJWT})
	if err != nil {
		t.Fatalf("jwtService.PublicKeySignAndEncode() err = %v", err)
	}
	compact, err := signedCompactJWTFromResponse(signResponse)
	if err != nil {
		t.Fatalf("JwtSignResponse_Err failed: %v", err)
	}
	validator := &pb.JwtValidator{
		ExpectedTypeHeader: &pb.StringValue{Value: "JWT"},
	}
	verifyResponse, err := jwtService.PublicKeyVerifyAndDecode(ctx, &pb.JwtVerifyRequest{Keyset: publicKeyset, SignedCompactJwt: compact, Validator: validator})
	if err != nil {
		t.Fatalf("jwtVerifySignature failed: %v", err)
	}
	if _, err := verifiedJWTFromResponse(verifyResponse); err == nil {
		t.Fatalf("JwtVerifyResponse_Err: nil want error")
	}
}

func TestJWTPublicKeySignAndEncodeVerifyAndDecode(t *testing.T) {
	keysetService := &services.KeysetService{}
	jwtService := &services.JWTService{}

	ctx := context.Background()
	template, err := proto.Marshal(jwt.ES256Template())
	if err != nil {
		t.Fatalf("proto.Marshal(jwt.ES256Template()) failed: %v", err)
	}
	privateKeyset, err := genKeyset(ctx, keysetService, template)
	if err != nil {
		t.Fatalf("genKeyset failed: %v", err)
	}
	publicKeyset, err := pubKeyset(ctx, keysetService, privateKeyset)
	if err != nil {
		t.Fatalf("pubKeyset failed: %v", err)
	}
	rawJWT := &pb.JwtToken{
		Subject: &pb.StringValue{Value: "tink-subject"},
	}
	signResponse, err := jwtService.PublicKeySignAndEncode(ctx, &pb.JwtSignRequest{Keyset: privateKeyset, RawJwt: rawJWT})
	if err != nil {
		t.Fatalf("jwtService.PublicKeySignAndEncode() err = %v", err)
	}
	compact, err := signedCompactJWTFromResponse(signResponse)
	if err != nil {
		t.Fatalf("JwtSignResponse_Err failed: %v", err)
	}
	validator := &pb.JwtValidator{
		AllowMissingExpiration: true,
	}
	verifyResponse, err := jwtService.PublicKeyVerifyAndDecode(ctx, &pb.JwtVerifyRequest{Keyset: publicKeyset, SignedCompactJwt: compact, Validator: validator})
	if err != nil {
		t.Fatalf("jwtVerifySignature failed: %v", err)
	}
	verifiedJWT, err := verifiedJWTFromResponse(verifyResponse)
	if err != nil {
		t.Fatalf("JwtVerifyResponse_Err: %v", err)
	}
	if !cmp.Equal(verifiedJWT, rawJWT, protocmp.Transform()) {
		t.Errorf("verifiedJWT doesn't match expected value: (+ got, - want) %v", cmp.Diff(verifiedJWT, rawJWT, protocmp.Transform()))
	}
}
