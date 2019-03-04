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

	"github.com/google/tink/go/core/primitiveset"
	"github.com/google/tink/go/core/registry"
	"github.com/google/tink/go/keyset"
	"github.com/google/tink/go/tink"
)

// NewHybridEncrypt returns an HybridEncrypt primitive from the given keyset handle.
func NewHybridEncrypt(h *keyset.Handle) (tink.HybridEncrypt, error) {
	return NewHybridEncryptWithKeyManager(h, nil /*keyManager*/)
}

// NewHybridEncryptWithKeyManager returns an HybridEncrypt primitive from the given keyset handle and custom key manager.
func NewHybridEncryptWithKeyManager(h *keyset.Handle, km registry.KeyManager) (tink.HybridEncrypt, error) {
	ps, err := h.PrimitivesWithKeyManager(km)
	if err != nil {
		return nil, fmt.Errorf("hybrid_factory: cannot obtain primitive set: %s", err)
	}
	return newEncryptPrimitiveSet(ps), nil
}

// encryptPrimitiveSet is an HybridEncrypt implementation that uses the underlying primitive set for encryption.
type encryptPrimitiveSet struct {
	ps *primitiveset.PrimitiveSet
}

// Asserts that primitiveSet implements the HybridEncrypt interface.
var _ tink.HybridEncrypt = (*encryptPrimitiveSet)(nil)

func newEncryptPrimitiveSet(ps *primitiveset.PrimitiveSet) *encryptPrimitiveSet {
	ret := new(encryptPrimitiveSet)
	ret.ps = ps
	return ret
}

// Encrypt encrypts the given plaintext with the given additional authenticated data.
// It returns the concatenation of the primary's identifier and the ciphertext.
func (a *encryptPrimitiveSet) Encrypt(pt, ad []byte) ([]byte, error) {
	primary := a.ps.Primary
	var p = (primary.Primitive).(tink.HybridEncrypt)
	ct, err := p.Encrypt(pt, ad)
	if err != nil {
		return nil, err
	}
	var ret []byte
	ret = append(ret, primary.Prefix...)
	ret = append(ret, ct...)
	return ret, nil
}
