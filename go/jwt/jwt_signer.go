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

// Signer is the interface for signing JWTs.
// See RFC 7519 and RFC 7515. Security guarantees: similar to tink.Signer.
type Signer interface {
	// Computes a signature, and encodes the JWT and the signature in the JWS compact serialization format.
	SignAndEncode(rawJWT *RawJWT) (string, error)
}
