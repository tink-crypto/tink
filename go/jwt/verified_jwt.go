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

package jwt

import (
	"fmt"
	"time"
)

// VerifiedJWT is a verified JWT token.
type VerifiedJWT struct {
	token *RawJWT
}

// newVerifiedJWT generates a new VerifiedJWT
func newVerifiedJWT(rawJWT *RawJWT) (*VerifiedJWT, error) {
	if rawJWT == nil {
		return nil, fmt.Errorf("rawJWT can't be nil")
	}
	return &VerifiedJWT{
		token: rawJWT,
	}, nil
}

// JSONPayload marshals a VerifiedJWT payload to JSON.
func (v *VerifiedJWT) JSONPayload() ([]byte, error) {
	return v.token.JSONPayload()
}

// HasTypeHeader return whether a RawJWT contains a type header.
func (v *VerifiedJWT) HasTypeHeader() bool {
	return v.token.HasTypeHeader()
}

// TypeHeader returns the JWT type header.
func (v *VerifiedJWT) TypeHeader() (string, error) {
	return v.token.TypeHeader()
}

// HasAudiences checks whether a JWT contains the audience claim ('aud').
func (v *VerifiedJWT) HasAudiences() bool {
	return v.token.HasAudiences()
}

// Audiences returns a list of audiences from the 'aud' claim.
// If the 'aud' claim is a single string, it is converted into a list with a single entry.
func (v *VerifiedJWT) Audiences() ([]string, error) {
	return v.token.Audiences()
}

// HasSubject checks whether a JWT contains an issuer claim ('sub').
func (v *VerifiedJWT) HasSubject() bool {
	return v.token.HasSubject()
}

// Subject returns the subject claim ('sub') or an error if no claim is present.
func (v *VerifiedJWT) Subject() (string, error) {
	return v.token.Subject()
}

// HasIssuer checks whether a JWT contains an issuer claim ('iss').
func (v *VerifiedJWT) HasIssuer() bool {
	return v.token.HasIssuer()
}

// Issuer returns the issuer claim ('iss') or an error if no claim is present.
func (v *VerifiedJWT) Issuer() (string, error) {
	return v.token.Issuer()
}

// HasJWTID checks whether a JWT contains an JWT ID claim ('jti').
func (v *VerifiedJWT) HasJWTID() bool {
	return v.token.HasJWTID()
}

// JWTID returns the JWT ID claim ('jti') or an error if no claim is present.
func (v *VerifiedJWT) JWTID() (string, error) {
	return v.token.JWTID()
}

// HasIssuedAt checks whether a JWT contains an issued at claim ('iat').
func (v *VerifiedJWT) HasIssuedAt() bool {
	return v.token.HasIssuedAt()
}

// IssuedAt returns the issued at claim ('iat') or an error if no claim is present.
func (v *VerifiedJWT) IssuedAt() (time.Time, error) {
	return v.token.IssuedAt()
}

// HasExpiration checks whether a JWT contains an expiration time claim ('exp').
func (v *VerifiedJWT) HasExpiration() bool {
	return v.token.HasExpiration()
}

// ExpiresAt returns the expiration claim ('exp') or an error if no claim is present.
func (v *VerifiedJWT) ExpiresAt() (time.Time, error) {
	return v.token.ExpiresAt()
}

// HasNotBefore checks whether a JWT contains a not before claim ('nbf').
func (v *VerifiedJWT) HasNotBefore() bool {
	return v.token.HasNotBefore()
}

// NotBefore returns the not before claim ('nbf') or an error if no claim is present.
func (v *VerifiedJWT) NotBefore() (time.Time, error) {
	return v.token.NotBefore()
}

// HasStringClaim checks whether a claim of type string is present.
func (v *VerifiedJWT) HasStringClaim(name string) bool {
	return v.token.HasStringClaim(name)
}

// StringClaim returns a custom string claim or an error if no claim is present.
func (v *VerifiedJWT) StringClaim(name string) (string, error) {
	return v.token.StringClaim(name)
}

// HasNumberClaim checks whether a claim of type number is present.
func (v *VerifiedJWT) HasNumberClaim(name string) bool {
	return v.token.HasNumberClaim(name)
}

// NumberClaim returns a custom number claim or an error if no claim is present.
func (v *VerifiedJWT) NumberClaim(name string) (float64, error) {
	return v.token.NumberClaim(name)
}

// HasBooleanClaim checks whether a claim of type boolean is present.
func (v *VerifiedJWT) HasBooleanClaim(name string) bool {
	return v.token.HasBooleanClaim(name)
}

// BooleanClaim returns a custom bool claim or an error if no claim is present.
func (v *VerifiedJWT) BooleanClaim(name string) (bool, error) {
	return v.token.BooleanClaim(name)
}

// HasNullClaim checks whether a claim of type null is present.
func (v *VerifiedJWT) HasNullClaim(name string) bool {
	return v.token.HasNullClaim(name)
}

// HasArrayClaim checks whether a claim of type list is present.
func (v *VerifiedJWT) HasArrayClaim(name string) bool {
	return v.token.HasArrayClaim(name)
}

// ArrayClaim returns a slice representing a JSON array for a claim or an error if the claim is empty.
func (v *VerifiedJWT) ArrayClaim(name string) ([]interface{}, error) {
	return v.token.ArrayClaim(name)
}

// HasObjectClaim checks whether a claim of type JSON object is present.
func (v *VerifiedJWT) HasObjectClaim(name string) bool {
	return v.token.HasObjectClaim(name)
}

// ObjectClaim returns a map representing a JSON object for a claim or an error if the claim is empty.
func (v *VerifiedJWT) ObjectClaim(name string) (map[string]interface{}, error) {
	return v.token.ObjectClaim(name)
}

// CustomClaimNames returns a list with the name of custom claims in a VerifiedJWT.
func (v *VerifiedJWT) CustomClaimNames() []string {
	return v.token.CustomClaimNames()
}
