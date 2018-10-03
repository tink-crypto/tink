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

package aead

import (
	"fmt"

	"github.com/google/tink/go/tink"
)

// New returns a AEAD primitive from the given keyset handle.
func New(handle *tink.KeysetHandle) (tink.AEAD, error) {
	return NewWithKeyManager(handle, nil /*keyManager*/)
}

// NewWithKeyManager returns a AEAD primitive from the given keyset handle and custom key manager.
func NewWithKeyManager(kh *tink.KeysetHandle, km tink.KeyManager) (tink.AEAD, error) {
	ps, err := tink.PrimitivesWithKeyManager(kh, km)
	if err != nil {
		return nil, fmt.Errorf("aead_factory: cannot obtain primitive set: %s", err)
	}
	var ret tink.AEAD = newPrimitiveSet(ps)
	return ret, nil
}

// primitiveSet is an AEAD implementation that uses the underlying primitive set for encryption
// and decryption.
type primitiveSet struct {
	ps *tink.PrimitiveSet
}

// Asserts that primitiveSet implements the AEAD interface.
var _ tink.AEAD = (*primitiveSet)(nil)

func newPrimitiveSet(ps *tink.PrimitiveSet) *primitiveSet {
	ret := new(primitiveSet)
	ret.ps = ps
	return ret
}

// Encrypt encrypts the given plaintext with the given additional authenticated data.
// It returns the concatenation of the primary's identifier and the ciphertext.
func (a *primitiveSet) Encrypt(pt, ad []byte) ([]byte, error) {
	primary := a.ps.Primary
	var p tink.AEAD = (primary.Primitive).(tink.AEAD)
	ct, err := p.Encrypt(pt, ad)
	if err != nil {
		return nil, err
	}
	var ret []byte
	ret = append(ret, primary.Prefix...)
	ret = append(ret, ct...)
	return ret, nil
}

// Decrypt decrypts the given ciphertext and authenticates it with the given
// additional authenticated data. It returns the corresponding plaintext if the
// ciphertext is authenticated.
func (a *primitiveSet) Decrypt(ct, ad []byte) ([]byte, error) {
	// try non-raw keys
	prefixSize := tink.NonRawPrefixSize
	if len(ct) > prefixSize {
		prefix := ct[:prefixSize]
		ctNoPrefix := ct[prefixSize:]
		entries, err := a.ps.EntriesForPrefix(string(prefix))
		if err == nil {
			for i := 0; i < len(entries); i++ {
				var p = (entries[i].Primitive).(tink.AEAD)
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
			var p = (entries[i].Primitive).(tink.AEAD)
			pt, err := p.Decrypt(ct, ad)
			if err == nil {
				return pt, nil
			}
		}
	}
	// nothing worked
	return nil, fmt.Errorf("aead_factory: decryption failed")
}
