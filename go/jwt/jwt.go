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

// Package jwt implements a subset of JSON Web Token (JWT) as defined by RFC 7519 (https://tools.ietf.org/html/rfc7519) that is considered safe and most often used.
package jwt

import (
	"fmt"

	"github.com/google/tink/go/core/registry"
)

func init() {
	if err := registry.RegisterKeyManager(new(jwtHMACKeyManager)); err != nil {
		panic(fmt.Sprintf("jwt.init() failed registering JWT HMAC key manger: %v", err))
	}
	if err := registry.RegisterKeyManager(new(jwtECDSAVerifierKeyManager)); err != nil {
		panic(fmt.Sprintf("jwt.init() failed registering JWT ECDSA verifier key manger: %v", err))
	}
}
