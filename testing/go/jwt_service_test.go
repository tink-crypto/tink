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

	dpb "google.golang.org/protobuf/types/known/durationpb"
	spb "google.golang.org/protobuf/types/known/structpb"
	tpb "google.golang.org/protobuf/types/known/timestamppb"
	wpb "google.golang.org/protobuf/types/known/wrapperspb"
	"github.com/google/go-cmp/cmp"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/testing/protocmp"
	"github.com/google/tink/go/aead"
	"github.com/google/tink/go/jwt"
	"github.com/google/tink/go/signature"
	"github.com/google/tink/testing/go/services"
	pb "github.com/google/tink/testing/go/proto/testing_api_go_grpc"
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

func jwkSetFromResponse(response *pb.JwtToJwkSetResponse) (string, error) {
	switch r := response.Result.(type) {
	case *pb.JwtToJwkSetResponse_JwkSet:
		return r.JwkSet, nil
	case *pb.JwtToJwkSetResponse_Err:
		return "", errors.New(r.Err)
	default:
		return "", fmt.Errorf("response.Result has unexpected type %T", r)
	}
}

func keysetFromResponse(response *pb.JwtFromJwkSetResponse) ([]byte, error) {
	switch r := response.Result.(type) {
	case *pb.JwtFromJwkSetResponse_Keyset:
		return r.Keyset, nil
	case *pb.JwtFromJwkSetResponse_Err:
		return nil, errors.New(r.Err)
	default:
		return nil, fmt.Errorf("response.Result has unexpected type %T", r)
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

func TestSuccessfulJwtMacCreation(t *testing.T) {
	keysetService := &services.KeysetService{}
	jwtService := &services.JWTService{}
	ctx := context.Background()

	template, err := proto.Marshal(jwt.HS256Template())
	if err != nil {
		t.Fatalf("proto.Marshal(jwt.HS256Template()) failed: %v, want nil", err)
	}

	keyset, err := genKeyset(ctx, keysetService, template)
	if err != nil {
		t.Fatalf("genKeyset failed: %v", err)
	}

	result, err := jwtService.CreateJwtMac(ctx, &pb.CreationRequest{Keyset: keyset})
	if err != nil {
		t.Fatalf("CreateJwtMac with good keyset failed with gRPC error: %v, want nil", err)
	}
	if result.GetErr() != "" {
		t.Fatalf("CreateJwtMac with good keyset failed with result.GetErr() = %q, want empty string", result.GetErr())
	}
}

func TestFailingJwtMacCreation(t *testing.T) {
	keysetService := &services.KeysetService{}
	jwtService := &services.JWTService{}
	ctx := context.Background()

	// We use signature keys -- then we cannot create a JwtMac
	template, err := proto.Marshal(aead.AES128GCMKeyTemplate())
	if err != nil {
		t.Fatalf("proto.Marshal(signature.ECDSAP256KeyTemplate()) failed: %v", err)
	}

	badKeyset, err := genKeyset(ctx, keysetService, template)
	if err != nil {
		t.Fatalf("genKeyset failed: %v", err)
	}

	result, err := jwtService.CreateJwtMac(ctx, &pb.CreationRequest{Keyset: badKeyset})
	if err != nil {
		t.Fatalf("CreateJwtMac with bad keyset failed with gRPC error: %v", err)
	}
	if result.GetErr() == "" {
		t.Fatalf("result.GetErr() of bad keyset after CreateJwtMac is empty, want not empty")
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
		TypeHeader: &wpb.StringValue{Value: "JWT"},
		Issuer:     &wpb.StringValue{Value: "issuer"},
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
				TypeHeader: &wpb.StringValue{Value: "JWT"},
				Issuer:     &wpb.StringValue{Value: "issuer"},
				Subject:    &wpb.StringValue{Value: "subject"},
				JwtId:      &wpb.StringValue{Value: "tink"},
				Audiences:  []string{"audience"},
				Expiration: &tpb.Timestamp{Seconds: 123456},
				NotBefore:  &tpb.Timestamp{Seconds: 12345},
				IssuedAt:   &tpb.Timestamp{Seconds: 1234},
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
				ExpectedTypeHeader: &wpb.StringValue{Value: "JWT"},
				ExpectedIssuer:     &wpb.StringValue{Value: "issuer"},
				ExpectedAudience:   &wpb.StringValue{Value: "audience"},
				Now:                &tpb.Timestamp{Seconds: 12345},
				ClockSkew:          &dpb.Duration{Seconds: 0},
			},
		},
		{
			tag: "without custom claims",
			rawJWT: &pb.JwtToken{
				TypeHeader: &wpb.StringValue{Value: "JWT"},
				Issuer:     &wpb.StringValue{Value: "issuer"},
				Subject:    &wpb.StringValue{Value: "subject"},
				Audiences:  []string{"audience"},
			},
			validator: &pb.JwtValidator{
				ExpectedTypeHeader:     &wpb.StringValue{Value: "JWT"},
				ExpectedIssuer:         &wpb.StringValue{Value: "issuer"},
				ExpectedAudience:       &wpb.StringValue{Value: "audience"},
				AllowMissingExpiration: true,
			},
		},
		{
			tag: "without expiration",
			rawJWT: &pb.JwtToken{
				Subject: &wpb.StringValue{Value: "subject"},
			},
			validator: &pb.JwtValidator{
				AllowMissingExpiration: true,
			},
		},
		{
			tag: "clock skew",
			rawJWT: &pb.JwtToken{
				Expiration: &tpb.Timestamp{Seconds: 1234},
			},
			validator: &pb.JwtValidator{
				Now:       &tpb.Timestamp{Seconds: 1235},
				ClockSkew: &dpb.Duration{Seconds: 2},
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
		TypeHeader: &wpb.StringValue{Value: "JWT"},
		Expiration: &tpb.Timestamp{Seconds: 123456},
		NotBefore:  &tpb.Timestamp{Seconds: 12345},
		IssuedAt:   &tpb.Timestamp{Seconds: 1234},
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
		ExpectedTypeHeader: &wpb.StringValue{Value: "JWT"},
		Now:                &tpb.Timestamp{Seconds: 12345},
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
				ExpectedTypeHeader: &wpb.StringValue{Value: "unexpected"},
				Now:                &tpb.Timestamp{Seconds: 12345},
			},
		},
		{
			tag: "expired token",
			validator: &pb.JwtValidator{
				ExpectedTypeHeader: &wpb.StringValue{Value: "JWT"},
				Now:                &tpb.Timestamp{Seconds: 999999999999},
			},
		},
		{
			tag: "expect issued in the past",
			validator: &pb.JwtValidator{
				ExpectedTypeHeader:    &wpb.StringValue{Value: "JWT"},
				Now:                   &tpb.Timestamp{Seconds: 1233},
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

func TestSuccessfulJwtSignVerifyCreation(t *testing.T) {
	keysetService := &services.KeysetService{}
	jwtService := &services.JWTService{}
	ctx := context.Background()

	template, err := proto.Marshal(jwt.ES256Template())
	if err != nil {
		t.Fatalf("proto.Marshal(hybrid.ES256Template()) failed: %v", err)
	}

	privateKeyset, err := genKeyset(ctx, keysetService, template)
	if err != nil {
		t.Fatalf("genKeyset failed: %v", err)
	}

	result, err := jwtService.CreateJwtPublicKeySign(ctx, &pb.CreationRequest{Keyset: privateKeyset})
	if err != nil {
		t.Fatalf("CreateJwtPublicKeySign with good keyset failed with gRPC error: %v, want nil", err)
	}
	if result.GetErr() != "" {
		t.Fatalf("CreateJwtPublicKeySign with good keyset failed with result.GetErr() = %q, want empty string", result.GetErr())
	}
}

func TestSuccessfulJwtVerifyCreation(t *testing.T) {
	keysetService := &services.KeysetService{}
	jwtService := &services.JWTService{}
	ctx := context.Background()

	template, err := proto.Marshal(jwt.ES256Template())
	if err != nil {
		t.Fatalf("proto.Marshal(hybrid.ES256Template()) failed: %v", err)
	}

	privateKeyset, err := genKeyset(ctx, keysetService, template)
	if err != nil {
		t.Fatalf("genKeyset failed: %v", err)
	}
	publicKeyset, err := pubKeyset(ctx, keysetService, privateKeyset)
	if err != nil {
		t.Fatalf("pubKeyset failed: %v", err)
	}

	result, err := jwtService.CreateJwtPublicKeyVerify(ctx, &pb.CreationRequest{Keyset: publicKeyset})
	if err != nil {
		t.Fatalf("CreateJwtPublicKeyVerify with good keyset failed with gRPC error: %v", err)
	}
	if result.GetErr() != "" {
		t.Fatalf("CreateJwtPublicKeyVerify with good keyset failed with result.GetErr() = %q, want empty string", result.GetErr())
	}
}

func TestFailingJwtSignCreation(t *testing.T) {
	keysetService := &services.KeysetService{}
	jwtService := &services.JWTService{}
	ctx := context.Background()

	// We use signature keys -- then we cannot create a hybrid encrypt
	template, err := proto.Marshal(signature.ECDSAP256KeyTemplate())
	if err != nil {
		t.Fatalf("proto.Marshal(signature.ECDSAP256KeyTemplate()) failed: %v", err)
	}

	privateKeyset, err := genKeyset(ctx, keysetService, template)
	if err != nil {
		t.Fatalf("genKeyset failed: %v", err)
	}

	result, err := jwtService.CreateJwtPublicKeySign(ctx, &pb.CreationRequest{Keyset: privateKeyset})
	if err != nil {
		t.Fatalf("CreateJwtPublicKeySign with bad keyset failed with gRPC error: %v", err)
	}
	if result.GetErr() == "" {
		t.Fatalf("CreateJwtPublicKeySign with bad keyset succeeded")
	}
}

func TestFailingJwtVerifyCreation(t *testing.T) {
	keysetService := &services.KeysetService{}
	jwtService := &services.JWTService{}
	ctx := context.Background()

	// We use signature keys -- then we cannot create a hybrid encrypt
	template, err := proto.Marshal(signature.ECDSAP256KeyTemplate())
	if err != nil {
		t.Fatalf("proto.Marshal(signature.ECDSAP256KeyTemplate()) failed: %v", err)
	}

	privateKeyset, err := genKeyset(ctx, keysetService, template)
	if err != nil {
		t.Fatalf("genKeyset failed: %v", err)
	}
	publicKeyset, err := pubKeyset(ctx, keysetService, privateKeyset)
	if err != nil {
		t.Fatalf("pubKeyset failed: %v", err)
	}

	result, err := jwtService.CreateJwtPublicKeyVerify(ctx, &pb.CreationRequest{Keyset: publicKeyset})
	if err != nil {
		t.Fatalf("CreateJwtPublicKeyVerify with good keyset failed with gRPC error: %v", err)
	}
	if result.GetErr() == "" {
		t.Fatalf("CreateJwtPublicKeyVerify with bad keyset succeeded")
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
		Subject: &wpb.StringValue{Value: "tink-subject"},
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
		Subject: &wpb.StringValue{Value: "tink-subject"},
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
		ExpectedTypeHeader: &wpb.StringValue{Value: "JWT"},
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
		Subject: &wpb.StringValue{Value: "tink-subject"},
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

func TestToJwkSetWithPrivateKeyFails(t *testing.T) {
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
	toJWKResponse, err := jwtService.ToJwkSet(ctx, &pb.JwtToJwkSetRequest{Keyset: privateKeyset})
	if err != nil {
		t.Fatalf("jwtService.ToJwkSet() err = %v, want nil", err)
	}
	if _, err := jwkSetFromResponse(toJWKResponse); err == nil {
		t.Fatalf("JwtToJwkSetResponse_Err: = nil, want error")
	}
}

func TestFromJwkSetPrivateKeyFails(t *testing.T) {
	jwtService := &services.JWTService{}
	ctx := context.Background()
	jwkES256PublicKey := `{
	  "keys":[{
	  "kty":"EC",
	  "crv":"P-256",
	  "x":"wO6uIxh8SkKOO8VjZXNRTteRcwCPE4_4JElKyaa0fcQ",
	  "y":"7oRiYhnmkP6nqrdXWgtsWUWq5uFRLJkhyVFiWPRB278",
		"d":"8oRinhnmkYjkqrdXWgtsWUWq5uFRLJkhyVFiWPRB278",
	  "use":"sig","alg":"ES256","key_ops":["verify"],
	  "kid":"EhuduQ"}]
	}`
	fromJWKResponse, err := jwtService.FromJwkSet(ctx, &pb.JwtFromJwkSetRequest{JwkSet: jwkES256PublicKey})
	if err != nil {
		t.Fatalf("jwtService.FromJwkSet() err = %v, want nil", err)
	}
	if _, err := keysetFromResponse(fromJWKResponse); err == nil {
		t.Fatalf("JwtFromJwkSetResponse_Err = nil, want error")
	}
}

func TestFromJwkToJwkSet(t *testing.T) {
	jwtService := &services.JWTService{}
	ctx := context.Background()
	jwkES256PublicKey := `{
	  "keys":[{
	  "kty":"EC",
	  "crv":"P-256",
	  "x":"wO6uIxh8SkKOO8VjZXNRTteRcwCPE4_4JElKyaa0fcQ",
	  "y":"7oRiYhnmkP6nqrdXWgtsWUWq5uFRLJkhyVFiWPRB278",
	  "use":"sig","alg":"ES256","key_ops":["verify"],
	  "kid":"EhuduQ"}]
	}`
	fromJWKResponse, err := jwtService.FromJwkSet(ctx, &pb.JwtFromJwkSetRequest{JwkSet: jwkES256PublicKey})
	if err != nil {
		t.Fatalf("jwtService.FromJwkSet() err = %v, want nil", err)
	}
	ks, err := keysetFromResponse(fromJWKResponse)
	if err != nil {
		t.Fatalf("JwtFromJwkSetResponse_Err: = %v, want nil", err)
	}
	toJWKResponse, err := jwtService.ToJwkSet(ctx, &pb.JwtToJwkSetRequest{Keyset: ks})
	if err != nil {
		t.Fatalf("jwtService.ToJwkSet() err = %v, want nil", err)
	}
	jwkSet, err := jwkSetFromResponse(toJWKResponse)
	if err != nil {
		t.Fatalf("JwtToJwkSetResponse_Err: = %v, want nil", err)
	}
	got := &spb.Struct{}
	if err := got.UnmarshalJSON([]byte(jwkSet)); err != nil {
		t.Fatalf("got.UnmarshalJSON() err = %v, want nil", err)
	}
	want := &spb.Struct{}
	if err := want.UnmarshalJSON([]byte(jwkES256PublicKey)); err != nil {
		t.Fatalf("want.UnmarshalJSON() err = %v, want nil", err)
	}
	if !cmp.Equal(want, got, protocmp.Transform()) {
		t.Errorf("mismatch in jwk sets: diff (-want,+got): %v", cmp.Diff(want, got, protocmp.Transform()))
	}
}
