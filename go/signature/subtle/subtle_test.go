// Copyright 2020 Google LLC
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

package subtle_test

import "github.com/google/tink/go/testutil"

type ecdsaSuite struct {
	testutil.WycheproofSuite
	TestGroups []*ecdsaGroup `json:"testGroups"`
}

type ecdsaGroup struct {
	testutil.WycheproofGroup
	JWK    *ecdsaJWK     `json:"jwk,omitempty"`
	KeyDER string        `json:"keyDer"`
	KeyPEM string        `json:"keyPem"`
	SHA    string        `json:"sha"`
	Type   string        `json:"type"`
	Key    *ecdsaTestKey `json:"key"`
	Tests  []*ecdsaCase  `json:"tests"`
}

type ecdsaCase struct {
	testutil.WycheproofCase
	Message   testutil.HexBytes `json:"msg"`
	Signature testutil.HexBytes `json:"sig"`
}

type ecdsaTestKey struct {
	Curve string `json:"curve"`
	Type  string `json:"type"`
	Wx    string `json:"wx"`
	Wy    string `json:"wy"`
}

type ecdsaJWK struct {
	JWK   string `json:"jwk"`
	Curve string `json:"crv"`
	Kid   string `json:"kid"`
	Kty   string `json:"kty"`
	X     string `json:"x"`
	Y     string `json:"y"`
}

type ed25519Suite struct {
	testutil.WycheproofSuite
	TestGroups []*ed25519Group `json:"testGroups"`
}

type ed25519Group struct {
	testutil.WycheproofGroup
	KeyDER string          `json:"keyDer"`
	KeyPEM string          `json:"keyPem"`
	SHA    string          `json:"sha"`
	Type   string          `json:"type"`
	Key    *ed25519TestKey `json:"key"`
	Tests  []*ed25519Case  `json:"tests"`
}

type ed25519Case struct {
	testutil.WycheproofCase
	Message   testutil.HexBytes `json:"msg"`
	Signature testutil.HexBytes `json:"sig"`
}

type ed25519TestKey struct {
	SK testutil.HexBytes `json:"sk"`
	PK testutil.HexBytes `json:"pk"`
}
