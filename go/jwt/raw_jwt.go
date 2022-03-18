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

	TypeHeader        *string
	WithoutExpiration bool
}

// RawJWT is an unsigned JSON Web Token (JWT), https://tools.ietf.org/html/rfc7519.
type RawJWT struct {
	jsonpb     *spb.Struct
	typeHeader *string
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
func NewRawJWTFromJSON(typeHeader *string, jsonPayload []byte) (*RawJWT, error) {
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

// JSONPayload marshals a RawJWT payload to JSON.
func (r *RawJWT) JSONPayload() ([]byte, error) {
	return r.jsonpb.MarshalJSON()
}

// HasTypeHeader returns whether a RawJWT contains a type header.
func (r *RawJWT) HasTypeHeader() bool {
	return r.typeHeader != nil
}

// TypeHeader returns the JWT type header.
func (r *RawJWT) TypeHeader() (string, error) {
	if !r.HasTypeHeader() {
		return "", fmt.Errorf("no type header present")
	}
	return *r.typeHeader, nil
}

// HasAudiences checks whether a JWT contains the audience claim ('aud').
func (r *RawJWT) HasAudiences() bool {
	return r.hasField(claimAudience)
}

// Audiences returns a list of audiences from the 'aud' claim. If the 'aud' claim is a single string, it is converted into a list with a single entry.
func (r *RawJWT) Audiences() ([]string, error) {
	aud, ok := r.field(claimAudience)
	if !ok {
		return nil, fmt.Errorf("no audience claim found")
	}
	if err := validateAudienceClaim(aud); err != nil {
		return nil, err
	}
	if val, isString := aud.GetKind().(*spb.Value_StringValue); isString {
		return []string{val.StringValue}, nil
	}
	s := []string{}
	for _, a := range aud.GetListValue().GetValues() {
		s = append(s, a.GetStringValue())
	}
	return s, nil
}

// HasSubject checks whether a JWT contains an issuer claim ('sub').
func (r *RawJWT) HasSubject() bool {
	return r.hasField(claimSubject)
}

// Subject returns the subject claim ('sub') or an error if no claim is present.
func (r *RawJWT) Subject() (string, error) {
	return r.stringClaim(claimSubject)
}

// HasIssuer checks whether a JWT contains an issuer claim ('iss').
func (r *RawJWT) HasIssuer() bool {
	return r.hasField(claimIssuer)
}

// Issuer returns the issuer claim ('iss') or an error if no claim is present.
func (r *RawJWT) Issuer() (string, error) {
	return r.stringClaim(claimIssuer)
}

// HasJWTID checks whether a JWT contains an JWT ID claim ('jti').
func (r *RawJWT) HasJWTID() bool {
	return r.hasField(claimJWTID)
}

// JWTID returns the JWT ID claim ('jti') or an error if no claim is present.
func (r *RawJWT) JWTID() (string, error) {
	return r.stringClaim(claimJWTID)
}

// HasIssuedAt checks whether a JWT contains an issued at claim ('iat').
func (r *RawJWT) HasIssuedAt() bool {
	return r.hasField(claimIssuedAt)
}

// IssuedAt returns the issued at claim ('iat') or an error if no claim is present.
func (r *RawJWT) IssuedAt() (time.Time, error) {
	return r.timeClaim(claimIssuedAt)
}

// HasExpiration checks whether a JWT contains an expiration time claim ('exp').
func (r *RawJWT) HasExpiration() bool {
	return r.hasField(claimExpiration)
}

// ExpiresAt returns the expiration claim ('exp') or an error if no claim is present.
func (r *RawJWT) ExpiresAt() (time.Time, error) {
	return r.timeClaim(claimExpiration)
}

// HasNotBefore checks whether a JWT contains a not before claim ('nbf').
func (r *RawJWT) HasNotBefore() bool {
	return r.hasField(claimNotBefore)
}

// NotBefore returns the not before claim ('nbf') or an error if no claim is present.
func (r *RawJWT) NotBefore() (time.Time, error) {
	return r.timeClaim(claimNotBefore)
}

// HasStringClaim checks whether a claim of type string is present.
func (r *RawJWT) HasStringClaim(name string) bool {
	return !isRegisteredClaim(name) && r.hasClaimOfKind(name, &spb.Value{Kind: &spb.Value_StringValue{}})
}

// StringClaim returns a custom string claim or an error if no claim is present.
func (r *RawJWT) StringClaim(name string) (string, error) {
	if isRegisteredClaim(name) {
		return "", fmt.Errorf("claim '%q' is a registered claim", name)
	}
	return r.stringClaim(name)
}

// HasNumberClaim checks whether a claim of type number is present.
func (r *RawJWT) HasNumberClaim(name string) bool {
	return !isRegisteredClaim(name) && r.hasClaimOfKind(name, &spb.Value{Kind: &spb.Value_NumberValue{}})
}

// NumberClaim returns a custom number claim or an error if no claim is present.
func (r *RawJWT) NumberClaim(name string) (float64, error) {
	if isRegisteredClaim(name) {
		return 0, fmt.Errorf("claim '%q' is a registered claim", name)
	}
	return r.numberClaim(name)
}

// HasBooleanClaim checks whether a claim of type boolean is present.
func (r *RawJWT) HasBooleanClaim(name string) bool {
	return r.hasClaimOfKind(name, &spb.Value{Kind: &spb.Value_BoolValue{}})
}

// BooleanClaim returns a custom bool claim or an error if no claim is present.
func (r *RawJWT) BooleanClaim(name string) (bool, error) {
	val, err := r.customClaim(name)
	if err != nil {
		return false, err
	}
	b, ok := val.Kind.(*spb.Value_BoolValue)
	if !ok {
		return false, fmt.Errorf("claim '%q' is not a boolean", name)
	}
	return b.BoolValue, nil
}

// HasNullClaim checks whether a claim of type null is present.
func (r *RawJWT) HasNullClaim(name string) bool {
	return r.hasClaimOfKind(name, &spb.Value{Kind: &spb.Value_NullValue{}})
}

// HasArrayClaim checks whether a claim of type list is present.
func (r *RawJWT) HasArrayClaim(name string) bool {
	return !isRegisteredClaim(name) && r.hasClaimOfKind(name, &spb.Value{Kind: &spb.Value_ListValue{}})
}

// ArrayClaim returns a slice representing a JSON array for a claim or an error if the claim is empty.
func (r *RawJWT) ArrayClaim(name string) ([]interface{}, error) {
	val, err := r.customClaim(name)
	if err != nil {
		return nil, err
	}
	if val.GetListValue() == nil {
		return nil, fmt.Errorf("claim '%q' is not a list", name)
	}
	return val.GetListValue().AsSlice(), nil
}

// HasObjectClaim checks whether a claim of type JSON object is present.
func (r *RawJWT) HasObjectClaim(name string) bool {
	return r.hasClaimOfKind(name, &spb.Value{Kind: &spb.Value_StructValue{}})
}

// ObjectClaim returns a map representing a JSON object for a claim or an error if the claim is empty.
func (r *RawJWT) ObjectClaim(name string) (map[string]interface{}, error) {
	val, err := r.customClaim(name)
	if err != nil {
		return nil, err
	}
	if val.GetStructValue() == nil {
		return nil, fmt.Errorf("claim '%q' is not a JSON object", name)
	}
	return val.GetStructValue().AsMap(), err
}

// CustomClaimNames returns a list with the name of custom claims in a RawJWT.
func (r *RawJWT) CustomClaimNames() []string {
	names := []string{}
	for key := range r.jsonpb.GetFields() {
		if !isRegisteredClaim(key) {
			names = append(names, key)
		}
	}
	return names
}

func (r *RawJWT) timeClaim(name string) (time.Time, error) {
	n, err := r.numberClaim(name)
	if err != nil {
		return time.Time{}, err
	}
	return time.Unix(int64(n), 0), err
}

func (r *RawJWT) numberClaim(name string) (float64, error) {
	val, ok := r.field(name)
	if !ok {
		return 0, fmt.Errorf("no '%q' claim found", name)
	}
	s, ok := val.Kind.(*spb.Value_NumberValue)
	if !ok {
		return 0, fmt.Errorf("claim '%q' is not a number", name)
	}
	return s.NumberValue, nil
}

func (r *RawJWT) stringClaim(name string) (string, error) {
	val, ok := r.field(name)
	if !ok {
		return "", fmt.Errorf("no '%q' claim found", name)
	}
	s, ok := val.Kind.(*spb.Value_StringValue)
	if !ok {
		return "", fmt.Errorf("claim '%q' is not a string", name)
	}
	if !utf8.ValidString(s.StringValue) {
		return "", fmt.Errorf("claim '%q' is not a valid utf-8 encoded string", name)
	}
	return s.StringValue, nil
}

func (r *RawJWT) hasClaimOfKind(name string, exp *spb.Value) bool {
	val, exist := r.field(name)
	if !exist || exp == nil {
		return false
	}
	var isKind bool
	switch exp.GetKind().(type) {
	case *spb.Value_StructValue:
		_, isKind = val.GetKind().(*spb.Value_StructValue)
	case *spb.Value_NullValue:
		_, isKind = val.GetKind().(*spb.Value_NullValue)
	case *spb.Value_BoolValue:
		_, isKind = val.GetKind().(*spb.Value_BoolValue)
	case *spb.Value_ListValue:
		_, isKind = val.GetKind().(*spb.Value_ListValue)
	case *spb.Value_StringValue:
		_, isKind = val.GetKind().(*spb.Value_StringValue)
	case *spb.Value_NumberValue:
		_, isKind = val.GetKind().(*spb.Value_NumberValue)
	default:
		isKind = false
	}
	return isKind
}

func (r *RawJWT) customClaim(name string) (*spb.Value, error) {
	if isRegisteredClaim(name) {
		return nil, fmt.Errorf("'%q' is a registered claim", name)
	}
	val, ok := r.field(name)
	if !ok {
		return nil, fmt.Errorf("claim '%q' not found", name)
	}
	return val, nil
}

func (r *RawJWT) hasField(name string) bool {
	_, ok := r.field(name)
	return ok
}

func (r *RawJWT) field(name string) (*spb.Value, bool) {
	val, ok := r.jsonpb.GetFields()[name]
	return val, ok
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
