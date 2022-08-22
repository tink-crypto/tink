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

package services

import (
	"bytes"
	"context"
	"fmt"
	"time"

	spb "google.golang.org/protobuf/types/known/structpb"
	tpb "google.golang.org/protobuf/types/known/timestamppb"
	wpb "google.golang.org/protobuf/types/known/wrapperspb"
	"github.com/google/tink/go/jwt"
	"github.com/google/tink/go/keyset"
	"github.com/google/tink/go/testkeyset"
	pb "github.com/google/tink/testing/go/proto/testing_api_go_grpc"
)

// JWTService implements the JWT testing service.
type JWTService struct {
	pb.JwtServer
}

func (s *JWTService) CreateJwtMac(ctx context.Context, req *pb.CreationRequest) (*pb.CreationResponse, error) {
	reader := keyset.NewBinaryReader(bytes.NewReader(req.Keyset))
	handle, err := testkeyset.Read(reader)
	if err != nil {
		return &pb.CreationResponse{Err: err.Error()}, nil
	}
	_, err = jwt.NewMAC(handle)
	if err != nil {
		return &pb.CreationResponse{Err: err.Error()}, nil
	}
	return &pb.CreationResponse{}, nil
}

func (s *JWTService) CreateJwtPublicKeySign(ctx context.Context, req *pb.CreationRequest) (*pb.CreationResponse, error) {
	reader := keyset.NewBinaryReader(bytes.NewReader(req.Keyset))
	handle, err := testkeyset.Read(reader)
	if err != nil {
		return &pb.CreationResponse{Err: err.Error()}, nil
	}
	_, err = jwt.NewSigner(handle)
	if err != nil {
		return &pb.CreationResponse{Err: err.Error()}, nil
	}
	return &pb.CreationResponse{}, nil
}

func (s *JWTService) CreateJwtPublicKeyVerify(ctx context.Context, req *pb.CreationRequest) (*pb.CreationResponse, error) {
	reader := keyset.NewBinaryReader(bytes.NewReader(req.Keyset))
	handle, err := testkeyset.Read(reader)
	if err != nil {
		return &pb.CreationResponse{Err: err.Error()}, nil
	}
	_, err = jwt.NewVerifier(handle)
	if err != nil {
		return &pb.CreationResponse{Err: err.Error()}, nil
	}
	return &pb.CreationResponse{}, nil
}

func refString(s *wpb.StringValue) *string {
	if s == nil {
		return nil
	}
	v := s.GetValue()
	return &v
}

func refTime(t *tpb.Timestamp) *time.Time {
	if t == nil {
		return nil
	}
	v := time.Unix(t.GetSeconds(), 0)
	return &v
}

func arrayClaimToJSONString(array []interface{}) (string, error) {
	lv, err := spb.NewList(array)
	if err != nil {
		return "", err
	}
	b, err := lv.MarshalJSON()
	if err != nil {
		return "", err
	}
	return string(b), nil
}

func jsonStringToArrayClaim(stringArray string) ([]interface{}, error) {
	s := spb.NewListValue(&spb.ListValue{})
	if err := s.UnmarshalJSON([]byte(stringArray)); err != nil {
		return nil, err
	}
	if s.GetListValue() == nil {
		return nil, fmt.Errorf("invalid list")
	}
	return s.GetListValue().AsSlice(), nil
}

func objectClaimToJSONString(o map[string]interface{}) (string, error) {
	s, err := spb.NewStruct(o)
	if err != nil {
		return "", err
	}
	b, err := s.MarshalJSON()
	if err != nil {
		return "", err
	}
	return string(b), nil
}

func jsonStringToObjectClaim(obj string) (map[string]interface{}, error) {
	s := &spb.Struct{}
	if err := s.UnmarshalJSON([]byte(obj)); err != nil {
		return nil, err
	}
	return s.AsMap(), nil
}

func customClaimsFromProto(cc map[string]*pb.JwtClaimValue) (map[string]interface{}, error) {
	r := map[string]interface{}{}
	for key, val := range cc {
		switch val.Kind.(type) {
		case *pb.JwtClaimValue_NullValue:
			r[key] = nil
		case *pb.JwtClaimValue_StringValue:
			r[key] = val.GetStringValue()
		case *pb.JwtClaimValue_NumberValue:
			r[key] = val.GetNumberValue()
		case *pb.JwtClaimValue_BoolValue:
			r[key] = val.GetBoolValue()
		case *pb.JwtClaimValue_JsonArrayValue:
			a, err := jsonStringToArrayClaim(val.GetJsonArrayValue())
			if err != nil {
				return nil, err
			}
			r[key] = a
		case *pb.JwtClaimValue_JsonObjectValue:
			o, err := jsonStringToObjectClaim(val.GetJsonObjectValue())
			if err != nil {
				return nil, err
			}
			r[key] = o
		default:
			return nil, fmt.Errorf("unsupported type")
		}
	}
	return r, nil
}

func tokenFromProto(t *pb.JwtToken) (*jwt.RawJWT, error) {
	if t == nil {
		return nil, nil
	}
	ccs, err := customClaimsFromProto(t.GetCustomClaims())
	if err != nil {
		return nil, err
	}
	opts := &jwt.RawJWTOptions{
		TypeHeader:   refString(t.GetTypeHeader()),
		Audiences:    t.GetAudiences(),
		Subject:      refString(t.GetSubject()),
		Issuer:       refString(t.GetIssuer()),
		JWTID:        refString(t.GetJwtId()),
		IssuedAt:     refTime(t.GetIssuedAt()),
		NotBefore:    refTime(t.GetNotBefore()),
		ExpiresAt:    refTime(t.GetExpiration()),
		CustomClaims: ccs,
	}
	if opts.ExpiresAt == nil {
		opts.WithoutExpiration = true
	}
	return jwt.NewRawJWT(opts)
}

func toStringValue(present bool, getValue func() (string, error), val **wpb.StringValue) error {
	if !present {
		return nil
	}
	v, err := getValue()
	if err != nil {
		return err
	}
	*val = &wpb.StringValue{Value: v}
	return nil
}

func toTimeValue(present bool, getValue func() (time.Time, error), val **tpb.Timestamp) error {
	if !present {
		return nil
	}
	v, err := getValue()
	if err != nil {
		return err
	}
	*val = &tpb.Timestamp{Seconds: v.Unix()}
	return nil
}

func tokenToProto(v *jwt.VerifiedJWT) (*pb.JwtToken, error) {
	t := &pb.JwtToken{
		CustomClaims: map[string]*pb.JwtClaimValue{},
	}
	if err := toStringValue(v.HasTypeHeader(), v.TypeHeader, &t.TypeHeader); err != nil {
		return nil, err
	}
	if err := toStringValue(v.HasIssuer(), v.Issuer, &t.Issuer); err != nil {
		return nil, err
	}
	if err := toStringValue(v.HasSubject(), v.Subject, &t.Subject); err != nil {
		return nil, err
	}
	if err := toStringValue(v.HasJWTID(), v.JWTID, &t.JwtId); err != nil {
		return nil, err
	}
	if err := toTimeValue(v.HasExpiration(), v.ExpiresAt, &t.Expiration); err != nil {
		return nil, err
	}
	if err := toTimeValue(v.HasIssuedAt(), v.IssuedAt, &t.IssuedAt); err != nil {
		return nil, err
	}
	if err := toTimeValue(v.HasNotBefore(), v.NotBefore, &t.NotBefore); err != nil {
		return nil, err
	}
	if v.HasAudiences() {
		aud, err := v.Audiences()
		if err != nil {
			return nil, err
		}
		t.Audiences = aud
	}

	for _, name := range v.CustomClaimNames() {
		if v.HasArrayClaim(name) {
			array, err := v.ArrayClaim(name)
			if err != nil {
				return nil, err
			}
			s, err := arrayClaimToJSONString(array)
			if err != nil {
				return nil, err
			}
			t.CustomClaims[name] = &pb.JwtClaimValue{Kind: &pb.JwtClaimValue_JsonArrayValue{JsonArrayValue: s}}
			continue
		}
		if v.HasObjectClaim(name) {
			m, err := v.ObjectClaim(name)
			if err != nil {
				return nil, err
			}
			o, err := objectClaimToJSONString(m)
			if err != nil {
				return nil, err
			}
			t.CustomClaims[name] = &pb.JwtClaimValue{Kind: &pb.JwtClaimValue_JsonObjectValue{JsonObjectValue: o}}
			continue
		}
		if v.HasNullClaim(name) {
			t.CustomClaims[name] = &pb.JwtClaimValue{Kind: &pb.JwtClaimValue_NullValue{}}
			continue
		}
		if v.HasStringClaim(name) {
			s, err := v.StringClaim(name)
			if err != nil {
				return nil, err
			}
			t.CustomClaims[name] = &pb.JwtClaimValue{Kind: &pb.JwtClaimValue_StringValue{StringValue: s}}
			continue
		}
		if v.HasBooleanClaim(name) {
			b, err := v.BooleanClaim(name)
			if err != nil {
				return nil, err
			}
			t.CustomClaims[name] = &pb.JwtClaimValue{Kind: &pb.JwtClaimValue_BoolValue{BoolValue: b}}
			continue
		}
		if v.HasNumberClaim(name) {
			n, err := v.NumberClaim(name)
			if err != nil {
				return nil, err
			}
			t.CustomClaims[name] = &pb.JwtClaimValue{Kind: &pb.JwtClaimValue_NumberValue{NumberValue: n}}
			continue
		}
		return nil, fmt.Errorf("claim %q of unsupported type", name)
	}

	return t, nil
}

func validatorFromProto(v *pb.JwtValidator) (*jwt.Validator, error) {
	fixedNow := time.Now()
	if v.GetNow() != nil {
		fixedNow = *refTime(v.GetNow())
	}
	opts := &jwt.ValidatorOpts{
		ExpectedTypeHeader:     refString(v.GetExpectedTypeHeader()),
		ExpectedAudience:       refString(v.GetExpectedAudience()),
		ExpectedIssuer:         refString(v.GetExpectedIssuer()),
		ExpectIssuedInThePast:  v.GetExpectIssuedInThePast(),
		AllowMissingExpiration: v.GetAllowMissingExpiration(),
		IgnoreTypeHeader:       v.GetIgnoreTypeHeader(),
		IgnoreAudiences:        v.GetIgnoreAudience(),
		IgnoreIssuer:           v.GetIgnoreIssuer(),
		FixedNow:               fixedNow,
		ClockSkew:              time.Duration(v.GetClockSkew().GetSeconds()) * time.Second,
	}
	return jwt.NewValidator(opts)
}

func jwtSignResponseError(err error) *pb.JwtSignResponse {
	return &pb.JwtSignResponse{
		Result: &pb.JwtSignResponse_Err{err.Error()}}
}

func jwtVerifyResponseError(err error) *pb.JwtVerifyResponse {
	return &pb.JwtVerifyResponse{
		Result: &pb.JwtVerifyResponse_Err{err.Error()}}
}

func jwtToJWKSetResponseError(err error) *pb.JwtToJwkSetResponse {
	return &pb.JwtToJwkSetResponse{
		Result: &pb.JwtToJwkSetResponse_Err{err.Error()}}
}

func jwtFromJwkSetResponseError(err error) *pb.JwtFromJwkSetResponse {
	return &pb.JwtFromJwkSetResponse{
		Result: &pb.JwtFromJwkSetResponse_Err{err.Error()}}
}

func (s *JWTService) ComputeMacAndEncode(ctx context.Context, req *pb.JwtSignRequest) (*pb.JwtSignResponse, error) {
	reader := keyset.NewBinaryReader(bytes.NewReader(req.Keyset))
	handle, err := testkeyset.Read(reader)
	if err != nil {
		return jwtSignResponseError(err), nil
	}
	primitive, err := jwt.NewMAC(handle)
	if err != nil {
		return jwtSignResponseError(err), nil
	}
	rawJWT, err := tokenFromProto(req.GetRawJwt())
	if err != nil {
		return jwtSignResponseError(err), nil
	}
	compact, err := primitive.ComputeMACAndEncode(rawJWT)
	if err != nil {
		return jwtSignResponseError(err), nil
	}
	return &pb.JwtSignResponse{
		Result: &pb.JwtSignResponse_SignedCompactJwt{compact},
	}, nil
}

func (s *JWTService) VerifyMacAndDecode(ctx context.Context, req *pb.JwtVerifyRequest) (*pb.JwtVerifyResponse, error) {
	reader := keyset.NewBinaryReader(bytes.NewReader(req.Keyset))
	handle, err := testkeyset.Read(reader)
	if err != nil {
		return jwtVerifyResponseError(err), nil
	}
	primitive, err := jwt.NewMAC(handle)
	if err != nil {
		return jwtVerifyResponseError(err), nil
	}
	validator, err := validatorFromProto(req.GetValidator())
	if err != nil {
		return jwtVerifyResponseError(err), nil
	}
	verified, err := primitive.VerifyMACAndDecode(req.GetSignedCompactJwt(), validator)
	if err != nil {
		return jwtVerifyResponseError(err), nil
	}
	verifiedJWT, err := tokenToProto(verified)
	if err != nil {
		return jwtVerifyResponseError(err), nil
	}
	return &pb.JwtVerifyResponse{
		Result: &pb.JwtVerifyResponse_VerifiedJwt{verifiedJWT},
	}, nil
}

func (s *JWTService) PublicKeySignAndEncode(ctx context.Context, req *pb.JwtSignRequest) (*pb.JwtSignResponse, error) {
	reader := keyset.NewBinaryReader(bytes.NewReader(req.Keyset))
	handle, err := testkeyset.Read(reader)
	if err != nil {
		return jwtSignResponseError(err), nil
	}
	signer, err := jwt.NewSigner(handle)
	if err != nil {
		return jwtSignResponseError(err), nil
	}
	rawJWT, err := tokenFromProto(req.GetRawJwt())
	if err != nil {
		return jwtSignResponseError(err), nil
	}
	compact, err := signer.SignAndEncode(rawJWT)
	if err != nil {
		return jwtSignResponseError(err), nil
	}
	return &pb.JwtSignResponse{
		Result: &pb.JwtSignResponse_SignedCompactJwt{compact},
	}, nil
}

func (s *JWTService) PublicKeyVerifyAndDecode(ctx context.Context, req *pb.JwtVerifyRequest) (*pb.JwtVerifyResponse, error) {
	reader := keyset.NewBinaryReader(bytes.NewReader(req.Keyset))
	handle, err := testkeyset.Read(reader)
	if err != nil {
		return jwtVerifyResponseError(err), nil
	}
	verifier, err := jwt.NewVerifier(handle)
	if err != nil {
		return jwtVerifyResponseError(err), nil
	}
	validator, err := validatorFromProto(req.GetValidator())
	if err != nil {
		return jwtVerifyResponseError(err), nil
	}
	verified, err := verifier.VerifyAndDecode(req.GetSignedCompactJwt(), validator)
	if err != nil {
		return jwtVerifyResponseError(err), nil
	}
	verifiedJWT, err := tokenToProto(verified)
	if err != nil {
		return jwtVerifyResponseError(err), nil
	}
	return &pb.JwtVerifyResponse{
		Result: &pb.JwtVerifyResponse_VerifiedJwt{verifiedJWT},
	}, nil
}

func (s *JWTService) ToJwkSet(ctx context.Context, req *pb.JwtToJwkSetRequest) (*pb.JwtToJwkSetResponse, error) {
	ks, err := keyset.NewBinaryReader(bytes.NewReader(req.GetKeyset())).Read()
	if err != nil {
		return jwtToJWKSetResponseError(err), nil
	}
	handle, err := keyset.NewHandleWithNoSecrets(ks)
	if err != nil {
		return jwtToJWKSetResponseError(err), nil
	}
	jwkSet, err := jwt.JWKSetFromPublicKeysetHandle(handle)
	if err != nil {
		return jwtToJWKSetResponseError(err), nil
	}
	return &pb.JwtToJwkSetResponse{
		Result: &pb.JwtToJwkSetResponse_JwkSet{string(jwkSet)},
	}, nil
}

func (s *JWTService) FromJwkSet(ctx context.Context, req *pb.JwtFromJwkSetRequest) (*pb.JwtFromJwkSetResponse, error) {
	handle, err := jwt.JWKSetToPublicKeysetHandle([]byte(req.GetJwkSet()))
	if err != nil {
		return jwtFromJwkSetResponseError(err), nil
	}
	b := &bytes.Buffer{}
	if err := testkeyset.Write(handle, keyset.NewBinaryWriter(b)); err != nil {
		return jwtFromJwkSetResponseError(err), nil
	}
	return &pb.JwtFromJwkSetResponse{
		Result: &pb.JwtFromJwkSetResponse_Keyset{b.Bytes()},
	}, nil
}
