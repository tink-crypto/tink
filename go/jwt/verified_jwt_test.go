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
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/tink/go/jwt"
	"github.com/google/tink/go/keyset"
)

func createVerifiedJWT(rawJWT *jwt.RawJWT) (*jwt.VerifiedJWT, error) {
	kh, err := keyset.NewHandle(jwt.HS256Template())
	if err != nil {
		return nil, err
	}
	m, err := jwt.NewMAC(kh)
	if err != nil {
		return nil, err
	}
	compact, err := m.ComputeMACAndEncode(rawJWT)
	if err != nil {
		return nil, err
	}
	// This validator is purposely instantiated to always pass.
	// It isn't really validating much and probably shouldn't
	// be used like this out side of these tests.
	opts := &jwt.ValidatorOpts{
		AllowMissingExpiration: true,
		IgnoreTypeHeader:       true,
		IgnoreAudiences:        true,
		IgnoreIssuer:           true,
	}
	issuedAt, err := rawJWT.IssuedAt()
	if err == nil {
		opts.FixedNow = issuedAt
	}

	validator, err := jwt.NewValidator(opts)
	if err != nil {
		return nil, err
	}
	return m.VerifyMACAndDecode(compact, validator)
}

func TestGetRegisteredStringClaims(t *testing.T) {
	opts := &jwt.RawJWTOptions{
		TypeHeader:        refString("typeHeader"),
		Subject:           refString("test-subject"),
		Issuer:            refString("test-issuer"),
		JWTID:             refString("1"),
		WithoutExpiration: true,
	}
	rawJWT, err := jwt.NewRawJWT(opts)
	if err != nil {
		t.Fatalf("jwt.NewRawJWT(%v): %v", opts, err)
	}
	verifiedJWT, err := createVerifiedJWT(rawJWT)
	if err != nil {
		t.Fatalf("creating verifiedJWT: %v", err)
	}
	if !verifiedJWT.HasTypeHeader() {
		t.Errorf("verifiedJWT.HasTypeHeader() = false, want true")
	}
	if !verifiedJWT.HasSubject() {
		t.Errorf("verifiedJWT.HasSubject() = false, want true")
	}
	if !verifiedJWT.HasIssuer() {
		t.Errorf("verifiedJWT.HasIssuer() = false, want true")
	}
	if !verifiedJWT.HasJWTID() {
		t.Errorf("verifiedJWT.HasJWTID() = false, want true")
	}
	typeHeader, err := verifiedJWT.TypeHeader()
	if err != nil {
		t.Errorf("verifiedJWT.TypeHeader() err = %v, want nil", err)
	}
	if !cmp.Equal(typeHeader, *opts.TypeHeader) {
		t.Errorf("verifiedJWT.TypeHeader() = %q, want %q", typeHeader, *opts.TypeHeader)
	}
	subject, err := verifiedJWT.Subject()
	if err != nil {
		t.Errorf("verifiedJWT.Subject() err = %v, want nil", err)
	}
	if !cmp.Equal(subject, *opts.Subject) {
		t.Errorf("verifiedJWT.Subject() = %q, want %q", subject, *opts.Subject)
	}
	issuer, err := verifiedJWT.Issuer()
	if err != nil {
		t.Errorf("verifiedJWT.Issuer() err = %v, want nil", err)
	}
	if !cmp.Equal(issuer, *opts.Issuer) {
		t.Errorf("verifiedJWT.Issuer() = %q, want %q", issuer, *opts.Issuer)
	}
	jwtID, err := verifiedJWT.JWTID()
	if err != nil {
		t.Errorf("verifiedJWT.JWTID() err = %v, want nil", err)
	}
	if !cmp.Equal(jwtID, *opts.JWTID) {
		t.Errorf("verifiedJWT.JWTID() = %q, want %q", jwtID, *opts.JWTID)
	}
	if !cmp.Equal(verifiedJWT.CustomClaimNames(), []string{}) {
		t.Errorf("verifiedJWT.CustomClaimNames() = %q want %q", verifiedJWT.CustomClaimNames(), []string{})
	}
}

func TestGetRegisteredTimestampClaims(t *testing.T) {
	now := time.Now()
	opts := &jwt.RawJWTOptions{
		ExpiresAt: refTime(now.Add(time.Hour * 24).Unix()),
		IssuedAt:  refTime(now.Unix()),
		NotBefore: refTime(now.Add(-time.Hour * 2).Unix()),
	}
	rawJWT, err := jwt.NewRawJWT(opts)
	if err != nil {
		t.Fatalf("jwt.NewRawJWT(%v): %v", opts, err)
	}
	verifiedJWT, err := createVerifiedJWT(rawJWT)
	if err != nil {
		t.Fatalf("creating verifiedJWT: %v", err)
	}
	if !verifiedJWT.HasExpiration() {
		t.Errorf("verifiedJWT.HasExpiration() = false, want true")
	}
	if !verifiedJWT.HasIssuedAt() {
		t.Errorf("verifiedJWT.HasIssuedAt() = false, want true")
	}
	if !verifiedJWT.HasNotBefore() {
		t.Errorf("verifiedJWT.HasNotBefore() = false, want true")
	}
	expiresAt, err := verifiedJWT.ExpiresAt()
	if err != nil {
		t.Errorf("verifiedJWT.ExpiresAt() err = %v, want nil", err)
	}
	if !cmp.Equal(expiresAt, *opts.ExpiresAt) {
		t.Errorf("verifiedJWT.ExpiresAt() = %q, want %q", expiresAt, *opts.ExpiresAt)
	}
	issuedAt, err := verifiedJWT.IssuedAt()
	if err != nil {
		t.Errorf("verifiedJWT.IssuedAt() err = %v, want nil", err)
	}
	if !cmp.Equal(issuedAt, *opts.IssuedAt) {
		t.Errorf("verifiedJWT.IssuedAt() = %q, want %q", issuedAt, *opts.IssuedAt)
	}
	notBefore, err := verifiedJWT.NotBefore()
	if err != nil {
		t.Errorf("verifiedJWT.NotBefore() err = %v, want nil", err)
	}
	if !cmp.Equal(notBefore, *opts.NotBefore) {
		t.Errorf("verifiedJWT.NotBefore() = %q, want %q", notBefore, *opts.NotBefore)
	}
}

func TestGetAudiencesClaim(t *testing.T) {
	opts := &jwt.RawJWTOptions{
		WithoutExpiration: true,
		Audiences:         []string{"foo", "bar"},
	}
	rawJWT, err := jwt.NewRawJWT(opts)
	if err != nil {
		t.Fatalf("jwt.NewRawJWT(%v): %v", opts, err)
	}
	verifiedJWT, err := createVerifiedJWT(rawJWT)
	if err != nil {
		t.Fatalf("creating verifiedJWT: %v", err)
	}
	if !verifiedJWT.HasAudiences() {
		t.Errorf("verifiedJWT.HasAudiences() = false, want true")
	}
	audiences, err := verifiedJWT.Audiences()
	if err != nil {
		t.Errorf("verifiedJWT.Audiences() err = %v, want nil", err)
	}
	if !cmp.Equal(audiences, opts.Audiences) {
		t.Errorf("verifiedJWT.Audiences() = %q, want %q", audiences, opts.Audiences)
	}
}

func TestGetCustomClaims(t *testing.T) {
	opts := &jwt.RawJWTOptions{
		WithoutExpiration: true,
		CustomClaims: map[string]interface{}{
			"cc-null":   nil,
			"cc-num":    1.67,
			"cc-bool":   true,
			"cc-string": "goo",
			"cc-array":  []interface{}{"1", "2", "3"},
			"cc-object": map[string]interface{}{"cc-nested-num": 5.99},
		},
	}
	rawJWT, err := jwt.NewRawJWT(opts)
	if err != nil {
		t.Fatalf("jwt.NewRawJWT(%v): %v", opts, err)
	}
	verifiedJWT, err := createVerifiedJWT(rawJWT)
	if err != nil {
		t.Fatalf("creating verifiedJWT: %v", err)
	}
	wantCustomClaims := []string{"cc-num", "cc-bool", "cc-null", "cc-string", "cc-array", "cc-object"}
	if !cmp.Equal(verifiedJWT.CustomClaimNames(), wantCustomClaims, cmpopts.SortSlices(func(a, b string) bool { return a < b })) {
		t.Errorf("verifiedJWT.CustomClaimNames() = %q, want %q", verifiedJWT.CustomClaimNames(), wantCustomClaims)
	}
	if !verifiedJWT.HasNullClaim("cc-null") {
		t.Errorf("verifiedJWT.HasNullClaim('cc-null') = false, want true")
	}
	if !verifiedJWT.HasNumberClaim("cc-num") {
		t.Errorf("verifiedJWT.HasNumberClaim('cc-num') = false, want true")
	}
	if !verifiedJWT.HasBooleanClaim("cc-bool") {
		t.Errorf("verifiedJWT.HasBooleanClaim('cc-bool') = false, want true")
	}
	if !verifiedJWT.HasStringClaim("cc-string") {
		t.Errorf("verifiedJWT.HasStringClaim('cc-string') = false, want true")
	}
	if !verifiedJWT.HasArrayClaim("cc-array") {
		t.Errorf("verifiedJWT.HasArrayClaim('cc-array') = false, want true")
	}
	if !verifiedJWT.HasObjectClaim("cc-object") {
		t.Errorf("verifiedJWT.HasObjectClaim('cc-object') = false, want true")
	}
	number, err := verifiedJWT.NumberClaim("cc-num")
	if err != nil {
		t.Errorf("verifiedJWT.NumberClaim('cc-num') err = %v, want nil", err)
	}
	if !cmp.Equal(number, opts.CustomClaims["cc-num"]) {
		t.Errorf("verifiedJWT.NumberClaim('cc-num') = %f, want %f", number, opts.CustomClaims["cc-num"])
	}
	boolean, err := verifiedJWT.BooleanClaim("cc-bool")
	if err != nil {
		t.Errorf("verifiedJWT.BooleanClaim('cc-bool') err = %v, want nil", err)
	}
	if !cmp.Equal(boolean, opts.CustomClaims["cc-bool"]) {
		t.Errorf("verifiedJWT.BooleanClaim('cc-bool') = %v, want %v", boolean, opts.CustomClaims["cc-bool"])
	}
	str, err := verifiedJWT.StringClaim("cc-string")
	if err != nil {
		t.Errorf("verifiedJWT.StringClaim('cc-string') err = %v, want nil", err)
	}
	if !cmp.Equal(str, opts.CustomClaims["cc-string"]) {
		t.Errorf("verifiedJWT.StringClaim('cc-string') = %q, want %q", str, opts.CustomClaims["cc-string"])
	}
	array, err := verifiedJWT.ArrayClaim("cc-array")
	if err != nil {
		t.Errorf("verifiedJWT.ArrayClaim('cc-array') err = %v, want nil", err)
	}
	if !cmp.Equal(array, opts.CustomClaims["cc-array"]) {
		t.Errorf("verifiedJWT.ArrayClaim('cc-array') = %q, want %q", array, opts.CustomClaims["cc-array"])
	}
	object, err := verifiedJWT.ObjectClaim("cc-object")
	if err != nil {
		t.Errorf("verifiedJWT.ObjectClaim('cc-object') err = %v, want nil", err)
	}
	if !cmp.Equal(object, opts.CustomClaims["cc-object"]) {
		t.Errorf("verifiedJWT.ObjectClaim('cc-object') = %q, want %q", object, opts.CustomClaims["cc-object"])
	}
}

func TestCustomClaimIsFalseForWrongType(t *testing.T) {
	opts := &jwt.RawJWTOptions{
		WithoutExpiration: true,
		CustomClaims: map[string]interface{}{
			"cc-null":   nil,
			"cc-num":    1.67,
			"cc-bool":   true,
			"cc-string": "goo",
			"cc-array":  []interface{}{"1", "2", "3"},
			"cc-object": map[string]interface{}{"cc-nested-num": 5.99},
		},
	}
	rawJWT, err := jwt.NewRawJWT(opts)
	if err != nil {
		t.Fatalf("jwt.NewRawJWT(%v): %v", opts, err)
	}
	verifiedJWT, err := createVerifiedJWT(rawJWT)
	if err != nil {
		t.Fatalf("creating verifiedJWT: %v", err)
	}
	if verifiedJWT.HasNullClaim("cc-object") {
		t.Errorf("verifiedJWT.HasNullClaim('cc-object') = true, want false")
	}
	if verifiedJWT.HasNumberClaim("cc-bool") {
		t.Errorf("verifiedJWT.HasNumberClaim('cc-bool') = true, want false")
	}
	if verifiedJWT.HasStringClaim("cc-array") {
		t.Errorf("verifiedJWT.HasStringClaim('cc-array') = true, want false")
	}
	if verifiedJWT.HasBooleanClaim("cc-string") {
		t.Errorf("verifiedJWT.HasBooleanClaim('cc-string') = true, want false")
	}
	if verifiedJWT.HasArrayClaim("cc-null") {
		t.Errorf("verifiedJWT.HasArrayClaim('cc-null') = true, want false")
	}
	if verifiedJWT.HasObjectClaim("cc-num") {
		t.Errorf("verifiedJWT.HasObjectClaim('cc-num') = true, want false")
	}
}

func TestNoClaimsCallHasAndGet(t *testing.T) {
	opts := &jwt.RawJWTOptions{
		WithoutExpiration: true,
	}
	rawJWT, err := jwt.NewRawJWT(opts)
	if err != nil {
		t.Fatalf("jwt.NewRawJWT(%v): %v", opts, err)
	}
	verifiedJWT, err := createVerifiedJWT(rawJWT)
	if err != nil {
		t.Fatalf("creating verifiedJWT: %v", err)
	}
	if verifiedJWT.HasAudiences() {
		t.Errorf("verifiedJWT.HasAudiences() = true, want false")
	}
	if verifiedJWT.HasSubject() {
		t.Errorf("verifiedJWT.HasSubject() = true, want false")
	}
	if verifiedJWT.HasIssuer() {
		t.Errorf("verifiedJWT.HasIssuer() = true, want false")
	}
	if verifiedJWT.HasJWTID() {
		t.Errorf("verifiedJWT.HasJWTID() = true, want false")
	}
	if verifiedJWT.HasNotBefore() {
		t.Errorf("verifiedJWT.HasNotBefore() = true, want false")
	}
	if verifiedJWT.HasExpiration() {
		t.Errorf("verifiedJWT.HasExpiration() = true, want false")
	}
	if verifiedJWT.HasIssuedAt() {
		t.Errorf("verifiedJWT.HasIssuedAt() = true, want false")
	}
	if !cmp.Equal(verifiedJWT.CustomClaimNames(), []string{}) {
		t.Errorf("verifiedJWT.CustomClaimNames() = %q want %q", verifiedJWT.CustomClaimNames(), []string{})
	}
}

func TestCantGetRegisteredClaimsThroughCustomClaims(t *testing.T) {
	now := time.Now()
	opts := &jwt.RawJWTOptions{
		TypeHeader: refString("typeHeader"),
		Subject:    refString("test-subject"),
		Issuer:     refString("test-issuer"),
		JWTID:      refString("1"),
		Audiences:  []string{"foo", "bar"},
		ExpiresAt:  refTime(now.Add(time.Hour * 24).Unix()),
		IssuedAt:   refTime(now.Unix()),
		NotBefore:  refTime(now.Add(-time.Hour * 2).Unix()),
	}
	rawJWT, err := jwt.NewRawJWT(opts)
	if err != nil {
		t.Fatalf("jwt.NewRawJWT(%v): %v", opts, err)
	}
	verifiedJWT, err := createVerifiedJWT(rawJWT)
	if err != nil {
		t.Fatalf("creating verifiedJWT: %v", err)
	}
	for _, c := range []string{"iss", "sub", "aud", "jti", "exp", "nbf", "iat"} {
		if verifiedJWT.HasStringClaim(c) {
			t.Errorf("verifiedJWT.HasStringClaim(%q) = true, want false", c)
		}
		if verifiedJWT.HasNumberClaim(c) {
			t.Errorf("verifiedJWT.HasNumberClaim(%q) = true, want false", c)
		}
		if verifiedJWT.HasArrayClaim(c) {
			t.Errorf("verifiedJWT.HasArrayClaim(%q) = true, want false", c)
		}

		if _, err := verifiedJWT.StringClaim(c); err == nil {
			t.Errorf("verifiedJWT.StringClaim(%q) err = nil, want error", c)
		}
		if _, err := verifiedJWT.NumberClaim(c); err == nil {
			t.Errorf("verifiedJWT.NumberClaim(%q) err = nil, want error", c)
		}
		if _, err := verifiedJWT.ArrayClaim(c); err == nil {
			t.Errorf("verifiedJWT.ArrayClaim(%q) err = nil, want error", c)
		}
	}
}

func TestGetJSONPayload(t *testing.T) {
	opts := &jwt.RawJWTOptions{
		Subject:           refString("test-subject"),
		WithoutExpiration: true,
	}
	rawJWT, err := jwt.NewRawJWT(opts)
	if err != nil {
		t.Fatalf("jwt.NewRawJWT(%v): %v", opts, err)
	}
	verifiedJWT, err := createVerifiedJWT(rawJWT)
	if err != nil {
		t.Fatalf("creating verifiedJWT: %v", err)
	}
	j, err := verifiedJWT.JSONPayload()
	if err != nil {
		t.Errorf("verifiedJWT.JSONPayload() err = %v, want nil", err)
	}
	expected := `{"sub":"test-subject"}`
	if !cmp.Equal(string(j), expected) {
		t.Errorf("verifiedJWT.JSONPayload() = %q, want %q", string(j), expected)
	}
}
