// Copyright 2019 Google LLC
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

package signature_test

import (
	"encoding/base64"
	"fmt"
	"log"
	"testing"

	"github.com/google/tink/go/core/registry"
	"github.com/google/tink/go/keyset"
	"github.com/google/tink/go/signature"
	"github.com/google/tink/go/testutil"
)

func TestSignatureInit(t *testing.T) {
	// check for ECDSASignerKeyManager
	_, err := registry.GetKeyManager(testutil.ECDSASignerTypeURL)
	if err != nil {
		t.Errorf("unexpected error: %s", err)
	}

	// check for ECDSAVerifierKeyManager
	_, err = registry.GetKeyManager(testutil.ECDSAVerifierTypeURL)
	if err != nil {
		t.Errorf("unexpected error: %s", err)
	}
}

func Example() {
	kh, err := keyset.NewHandle(signature.ECDSAP256KeyTemplate()) // Other key templates can also be used.
	if err != nil {
		log.Fatal(err)
	}

	// TODO: save the private keyset to a safe location. DO NOT hardcode it in source code.
	// Consider encrypting it with a remote key in Cloud KMS, AWS KMS or HashiCorp Vault.
	// See https://github.com/google/tink/blob/master/docs/GOLANG-HOWTO.md#storing-and-loading-existing-keysets.

	s, err := signature.NewSigner(kh)
	if err != nil {
		log.Fatal(err)
	}

	msg := []byte("this data needs to be signed")
	sig, err := s.Sign(msg)
	if err != nil {
		log.Fatal(err)
	}

	pubkh, err := kh.Public()
	if err != nil {
		log.Fatal(err)
	}

	// TODO: share the public with the verifier.

	v, err := signature.NewVerifier(pubkh)
	if err != nil {
		log.Fatal(err)
	}

	if err := v.Verify(sig, msg); err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Message: %s\n", msg)
	fmt.Printf("Signature: %s\n", base64.StdEncoding.EncodeToString(sig))
}
