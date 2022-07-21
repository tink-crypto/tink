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

// Verifier is the interface for verifying signed JWTs.
// See RFC 7519 and RFC 7515. Security guarantees: similar to Verifier.
type Verifier interface {
	// Verifies and decodes a JWT token in the JWS compact serialization format.
	//
	// The JWT is validated against the rules in validator. That is, every claim
	// in validator must also be present in the JWT. For example, if validator
	// contains an issuer (iss) claim, the JWT must contain an identical claim.
	// The JWT can contain claims that are NOT in the validator. However, if the
	// JWT contains a list of audiences, the validator must also contain an
	// audience in the list.
	//
	// If the JWT contains timestamp claims such as expiration (exp), issued_at
	// (iat) or not_before (nbf), they will also be validated. validator allows to
	// set a clock skew, to deal with small clock differences among different
	// machines.
	VerifyAndDecode(compact string, validator *Validator) (*VerifiedJWT, error)
}
