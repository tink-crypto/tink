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

package hybrid

import (
	"fmt"

	"github.com/google/tink/go/core/cryptofmt"
	"github.com/google/tink/go/core/primitiveset"
	"github.com/google/tink/go/core/registry"
	"github.com/google/tink/go/keyset"
	"github.com/google/tink/go/tink"
)

// NewHybridDecrypt returns an HybridDecrypt primitive from the given keyset handle.
func NewHybridDecrypt(h *keyset.Handle) (tink.HybridDecrypt, error) {
	return NewHybridDecryptWithKeyManager(h, nil /*keyManager*/)
}

// NewHybridDecryptWithKeyManager returns an HybridDecrypt primitive from the given keyset handle and custom key manager.
func NewHybridDecryptWithKeyManager(h *keyset.Handle, km registry.KeyManager) (tink.HybridDecrypt, error) {
	ps, err := h.PrimitivesWithKeyManager(km)
	if err != nil {
		return nil, fmt.Errorf("hybrid_factory: cannot obtain primitive set: %s", err)
	}
	return newDecryptPrimitiveSet(ps), nil
}

// decryptPrimitiveSet is an HybridDecrypt implementation that uses the underlying primitive set for
// decryption.
type decryptPrimitiveSet struct {
	ps *primitiveset.PrimitiveSet
}

// Asserts that primitiveSet implements the HybridDecrypt interface.
var _ tink.HybridDecrypt = (*decryptPrimitiveSet)(nil)

func newDecryptPrimitiveSet(ps *primitiveset.PrimitiveSet) *decryptPrimitiveSet {
	ret := new(decryptPrimitiveSet)
	ret.ps = ps
	return ret
}

// Decrypt decrypts the given ciphertext and authenticates it with the given
// additional authenticated data. It returns the corresponding plaintext if the
// ciphertext is authenticated.
func (a *decryptPrimitiveSet) Decrypt(ct, ad []byte) ([]byte, error) {
	// try non-raw keys
	prefixSize := cryptofmt.NonRawPrefixSize
	if len(ct) > prefixSize {
		prefix := ct[:prefixSize]
		ctNoPrefix := ct[prefixSize:]
		entries, err := a.ps.EntriesForPrefix(string(prefix))
		if err == nil {
			for i := 0; i < len(entries); i++ {
				var p = (entries[i].Primitive).(tink.HybridDecrypt)
				pt, err := p.Decrypt(ctNoPrefix, ad)
				if err == nil {
					return pt, nil
				}
			}
		}
	}
	// try raw keys
	entries, err := a.ps.RawEntries()
	if err == nil {
		for i := 0; i < len(entries); i++ {
			var p = (entries[i].Primitive).(tink.HybridDecrypt)
			pt, err := p.Decrypt(ct, ad)
			if err == nil {
				return pt, nil
			}
		}
	}
	// nothing worked
	return nil, fmt.Errorf("hybrid_factory: decryption failed")
}
