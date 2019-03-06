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

// Package signature provides implementations of the Signer and Verifier primitives.
// To sign data using Tink you can use ECDSA or ED25519 key templates.
// Example:
//
// package main
//
// import (
//     "fmt"
//
//     "github.com/google/tink/go/signature"
//     "github.com/google/tink/go/keyset"
// )
//
// func main() {
//
//     kh, err := keyset.NewHandle(signature.ECDSAP256KeyTemplate()) // other key templates can also be used
//     if err != nil {
//         // handle the error
//     }
//
//     s := signature.NewSigner(kh)
//
//     a , err := s.Sign([]byte("this data needs to be signed"))
//     if err != nil {
//         // handle error
//     }
//
//     v := signature.NewVerifier(kh)
//
//     if err := v.Verify(a, []byte("this data needs to be signed")); err != nil {
//         // handle error
//     }
// }
package signature

import (
	"fmt"

	"github.com/google/tink/go/core/registry"
)

func init() {
	// ECDSA
	if err := registry.RegisterKeyManager(newECDSASignerKeyManager()); err != nil {
		panic(fmt.Sprintf("signature.init() failed: %v", err))
	}
	if err := registry.RegisterKeyManager(newECDSAVerifierKeyManager()); err != nil {
		panic(fmt.Sprintf("signature.init() failed: %v", err))
	}

	// ED25519
	if err := registry.RegisterKeyManager(newED25519SignerKeyManager()); err != nil {
		panic(fmt.Sprintf("signature.init() failed: %v", err))
	}
	if err := registry.RegisterKeyManager(newED25519VerifierKeyManager()); err != nil {
		panic(fmt.Sprintf("signature.init() failed: %v", err))
	}
}
