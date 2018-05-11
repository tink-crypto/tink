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

// GetPrimitive returns a Aead primitive from the given keyset handle.
func GetPrimitive(handle *tink.KeysetHandle) (tink.Aead, error) {
	return GetPrimitiveWithCustomerManager(handle, nil /*keyManager*/)
}

// GetPrimitiveWithCustomerManager returns a Aead primitive from the given
// keyset handle and custom key manager.
func GetPrimitiveWithCustomerManager(
	handle *tink.KeysetHandle, manager tink.KeyManager) (tink.Aead, error) {
	ps, err := tink.GetPrimitivesWithCustomManager(handle, manager)
	if err != nil {
		return nil, fmt.Errorf("aead_factory: cannot obtain primitive set: %s", err)
	}
	var ret tink.Aead = newPrimitiveSetAead(ps)
	return ret, nil
}

// primitiveSetAead is an Aead implementation that uses the underlying primitive
// set for encryption and decryption.
type primitiveSetAead struct {
	ps *tink.PrimitiveSet
}

// Asserts that primitiveSetAead implements the Aead interface.
var _ tink.Aead = (*primitiveSetAead)(nil)

// newPrimitiveSetAead creates a new instance of primitiveSetAead
func newPrimitiveSetAead(ps *tink.PrimitiveSet) *primitiveSetAead {
	ret := new(primitiveSetAead)
	ret.ps = ps
	return ret
}

// Encrypt encrypts the given plaintext with the given additional authenticated data.
// It returns the concatenation of the primary's identifier and the ciphertext.
func (a *primitiveSetAead) Encrypt(pt []byte, ad []byte) ([]byte, error) {
	primary := a.ps.Primary()
	var p tink.Aead = (primary.Primitive()).(tink.Aead)
	ct, err := p.Encrypt(pt, ad)
	if err != nil {
		return nil, err
	}
	var ret []byte
	ret = append(ret, primary.Identifier()...)
	ret = append(ret, ct...)
	return ret, nil
}

// Decrypt decrypts the given ciphertext and authenticates it with the given
// additional authenticated data. It returns the corresponding plaintext if the
// ciphertext is authenticated.
func (a *primitiveSetAead) Decrypt(ct []byte, ad []byte) ([]byte, error) {
	// try non-raw keys
	prefixSize := tink.NonRawPrefixSize
	if len(ct) > prefixSize {
		prefix := ct[:prefixSize]
		ctNoPrefix := ct[prefixSize:]
		entries, err := a.ps.GetPrimitivesWithByteIdentifier(prefix)
		if err == nil {
			for i := 0; i < len(entries); i++ {
				var p = (entries[i].Primitive()).(tink.Aead)
				pt, err := p.Decrypt(ctNoPrefix, ad)
				if err == nil {
					return pt, nil
				}
			}
		}
	}
	// try raw keys
	entries, err := a.ps.GetRawPrimitives()
	if err == nil {
		for i := 0; i < len(entries); i++ {
			var p = (entries[i].Primitive()).(tink.Aead)
			pt, err := p.Decrypt(ct, ad)
			if err == nil {
				return pt, nil
			}
		}
	}
	// nothing worked
	return nil, fmt.Errorf("aead_factory: decryption failed")
}
