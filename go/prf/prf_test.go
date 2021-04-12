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

package prf_test

import (
	"encoding/base64"
	"fmt"
	"log"

	"github.com/google/tink/go/keyset"
	"github.com/google/tink/go/prf"
)

func Example() {
	kh, err := keyset.NewHandle(prf.HMACSHA256PRFKeyTemplate())
	if err != nil {
		log.Fatal(err)
	}

	// TODO: save the keyset to a safe location. DO NOT hardcode it in source code.
	// Consider encrypting it with a remote key in Cloud KMS, AWS KMS or HashiCorp Vault.
	// See https://github.com/google/tink/blob/master/docs/GOLANG-HOWTO.md#storing-and-loading-existing-keysets.

	ps, err := prf.NewPRFSet(kh)
	if err != nil {
		log.Fatal(err)
	}

	msg := []byte("This is an ID needs to be redacted")
	output, err := ps.ComputePrimaryPRF(msg, 16)

	fmt.Printf("Message: %s\n", msg)
	fmt.Printf("Redacted: %s\n", base64.StdEncoding.EncodeToString(output))
}
