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

// Package jwt implements a subset of JSON Web Token (JWT) as defined by RFC 7519 (https://tools.ietf.org/html/rfc7519) that is considered safe and most often used.
package jwt

import (
	"fmt"
	"time"
	"unicode/utf8"

	spb "google.golang.org/protobuf/types/known/structpb"
)

const (
	claimIssuer     = "iss"
	claimSubject    = "sub"
	claimAudience   = "aud"
	claimExpiration = "exp"
	claimNotBefore  = "nbf"
	claimIssuedAt   = "iat"
	claimJWTID      = "jti"

	jwtTimestampMax = 253402300799
	jwtTimestampMin = 0
)

// RawJWTOptions represent an unsigned JSON Web Token (JWT), https://tools.ietf.org/html/rfc7519.
//
// It contains all payload claims and a subset of the headers. It does not
// contain any headers that depend on the key, such as "alg" or "kid", because
// these headers are chosen when the token is signed and encoded, and should not
// be chosen by the user. This ensures that the key can be changed without any
// changes to the user code.
type RawJWTOptions struct {
	Audiences    []string
	Audience     *string
	Subject      *string
	Issuer       *string
	JWTID        *string
	IssuedAt     *time.Time
	ExpiresAt    *time.Time
	NotBefore    *time.Time
	CustomClaims map[string]interface{}

	TypeHeader        string
	WithoutExpiration bool
}

// RawJWT is an unsigned JSON Web Token (JWT), https://tools.ietf.org/html/rfc7519.
type RawJWT struct {
	jsonpb     *spb.Struct
	typeHeader string
}

// NewRawJWT constructs a new RawJWT token based on the RawJwtOptions provided.
func NewRawJWT(opts *RawJWTOptions) (*RawJWT, error) {
	if opts == nil {
		return nil, fmt.Errorf("jwt options can't be nil")
	}
	payload, err := createPayload(opts)
	if err != nil {
		return nil, err
	}
	if err := validatePayload(payload); err != nil {
		return nil, err
	}
	return &RawJWT{
		jsonpb:     payload,
		typeHeader: opts.TypeHeader,
	}, nil
}

// NewRawJWTFromJSON builds a RawJWT from a marshaled JSON.
// Users shouldn't call this function and instead use NewRawJWT.
func NewRawJWTFromJSON(typeHeader string, jsonPayload []byte) (*RawJWT, error) {
	payload := &spb.Struct{}
	if err := payload.UnmarshalJSON(jsonPayload); err != nil {
		return nil, err
	}
	if err := validatePayload(payload); err != nil {
		return nil, err
	}
	return &RawJWT{
		jsonpb:     payload,
		typeHeader: typeHeader,
	}, nil
}

// JSONPayload a RawJWT marshals to JSON.
func (r *RawJWT) JSONPayload() ([]byte, error) {
	return r.jsonpb.MarshalJSON()
}

// createPayload creates a JSON payload from JWT options.
func createPayload(opts *RawJWTOptions) (*spb.Struct, error) {
	if err := validateCustomClaims(opts.CustomClaims); err != nil {
		return nil, err
	}
	if opts.ExpiresAt == nil && !opts.WithoutExpiration {
		return nil, fmt.Errorf("jwt options must contain an expiration or must be marked WithoutExpiration")
	}
	if opts.ExpiresAt != nil && opts.WithoutExpiration {
		return nil, fmt.Errorf("jwt options can't be marked WithoutExpiration when expiration is specified")
	}
	if opts.Audience != nil && opts.Audiences != nil {
		return nil, fmt.Errorf("jwt options can either contain a single Audience or a list of Audiences but not both")
	}

	payload := &spb.Struct{
		Fields: map[string]*spb.Value{},
	}
	setStringValue(payload, claimJWTID, opts.JWTID)
	setStringValue(payload, claimIssuer, opts.Issuer)
	setStringValue(payload, claimSubject, opts.Subject)
	setStringValue(payload, claimAudience, opts.Audience)
	setTimeValue(payload, claimIssuedAt, opts.IssuedAt)
	setTimeValue(payload, claimNotBefore, opts.NotBefore)
	setTimeValue(payload, claimExpiration, opts.ExpiresAt)
	setAudiences(payload, claimAudience, opts.Audiences)

	for k, v := range opts.CustomClaims {
		val, err := spb.NewValue(v)
		if err != nil {
			return nil, err
		}
		setValue(payload, k, val)
	}
	return payload, nil
}

func validatePayload(payload *spb.Struct) error {
	if payload.Fields == nil || len(payload.Fields) == 0 {
		return nil
	}
	if err := validateAudienceClaim(payload.Fields[claimAudience]); err != nil {
		return err
	}
	for claim, val := range payload.GetFields() {
		if isRegisteredTimeClaim(claim) {
			if err := validateTimeClaim(claim, val); err != nil {
				return err
			}
		}

		if isRegisteredStringClaim(claim) {
			if err := validateStringClaim(claim, val); err != nil {
				return err
			}
		}
	}
	return nil
}

func validateStringClaim(claim string, val *spb.Value) error {
	v, ok := val.Kind.(*spb.Value_StringValue)
	if !ok {
		return fmt.Errorf("claim: '%q' MUST be a string", claim)
	}
	if !utf8.ValidString(v.StringValue) {
		return fmt.Errorf("claim: '%q' isn't a valid UTF-8 string", claim)
	}
	return nil
}

func validateTimeClaim(claim string, val *spb.Value) error {
	if _, ok := val.Kind.(*spb.Value_NumberValue); !ok {
		return fmt.Errorf("claim %q MUST be a numeric value, ", claim)
	}
	t := int64(val.GetNumberValue())
	if t > jwtTimestampMax || t < jwtTimestampMin {
		return fmt.Errorf("invalid timestamp: '%d' for claim: %q", t, claim)
	}
	return nil
}

func validateAudienceClaim(val *spb.Value) error {
	if val == nil {
		return nil
	}
	_, isString := val.Kind.(*spb.Value_StringValue)
	l, isList := val.Kind.(*spb.Value_ListValue)
	if !isList && !isString {
		return fmt.Errorf("audience claim MUST be a list with at least one string or a single string value")
	}
	if isString {
		return validateStringClaim(claimAudience, val)
	}
	if l.ListValue != nil && len(l.ListValue.Values) == 0 {
		return fmt.Errorf("there MUST be at least one value present in the audience claim")
	}
	for _, aud := range l.ListValue.Values {
		v, ok := aud.Kind.(*spb.Value_StringValue)
		if !ok {
			return fmt.Errorf("audience value is not a string")
		}
		if !utf8.ValidString(v.StringValue) {
			return fmt.Errorf("audience value is not a valid UTF-8 string")
		}
	}
	return nil
}

func validateCustomClaims(cc map[string]interface{}) error {
	if cc == nil {
		return nil
	}
	for key := range cc {
		if isRegisteredClaim(key) {
			return fmt.Errorf("claim '%q' is a registered claim, it can't be declared as a custom claim", key)
		}
	}
	return nil
}

func setTimeValue(p *spb.Struct, claim string, val *time.Time) {
	if val == nil {
		return
	}
	setValue(p, claim, spb.NewNumberValue(float64(val.Unix())))
}

func setStringValue(p *spb.Struct, claim string, val *string) {
	if val == nil {
		return
	}
	setValue(p, claim, spb.NewStringValue(*val))
}

func setAudiences(p *spb.Struct, claim string, vals []string) {
	if vals == nil {
		return
	}
	audList := &spb.ListValue{
		Values: []*spb.Value{},
	}
	for _, aud := range vals {
		audList.Values = append(audList.Values, spb.NewStringValue(aud))
	}
	setValue(p, claim, spb.NewListValue(audList))
}

func setValue(p *spb.Struct, claim string, val *spb.Value) {
	if p.GetFields() == nil {
		p.Fields = make(map[string]*spb.Value)
	}
	p.GetFields()[claim] = val
}

func isRegisteredClaim(c string) bool {
	return isRegisteredStringClaim(c) || isRegisteredTimeClaim(c) || c == claimAudience
}

func isRegisteredStringClaim(c string) bool {
	return c == claimIssuer || c == claimSubject || c == claimJWTID
}

func isRegisteredTimeClaim(c string) bool {
	return c == claimExpiration || c == claimNotBefore || c == claimIssuedAt
}
