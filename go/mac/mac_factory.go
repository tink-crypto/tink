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

package mac

import (
	"fmt"

	"github.com/google/tink/go/tink"
)

// New creates a MAC primitive from the given keyset handle.
func New(kh *tink.KeysetHandle) (tink.MAC, error) {
	return NewWithKeyManager(kh, nil /*keyManager*/)
}

// NewWithKeyManager creates a MAC primitive from the given keyset handle and a custom key manager.
func NewWithKeyManager(kh *tink.KeysetHandle, km tink.KeyManager) (tink.MAC, error) {
	ps, err := tink.PrimitivesWithKeyManager(kh, km)
	if err != nil {
		return nil, fmt.Errorf("mac_factory: cannot obtain primitive set: %s", err)
	}
	var mac tink.MAC = newPrimitiveSet(ps)
	return mac, nil
}

// primitiveSet is a MAC implementation that uses the underlying primitive set to compute and
// verify MACs.
type primitiveSet struct {
	ps *tink.PrimitiveSet
}

// Asserts that primitiveSet implements the Mac interface.
var _ tink.MAC = (*primitiveSet)(nil)

func newPrimitiveSet(ps *tink.PrimitiveSet) *primitiveSet {
	ret := new(primitiveSet)
	ret.ps = ps
	return ret
}

// ComputeMAC calculates a MAC over the given data using the primary primitive
// and returns the concatenation of the primary's identifier and the calculated mac.
func (m *primitiveSet) ComputeMAC(data []byte) ([]byte, error) {
	primary := m.ps.Primary
	var primitive tink.MAC = (primary.Primitive).(tink.MAC)
	mac, err := primitive.ComputeMAC(data)
	if err != nil {
		return nil, err
	}
	var ret []byte
	ret = append(ret, primary.Prefix...)
	ret = append(ret, mac...)
	return ret, nil
}

var errInvalidMAC = fmt.Errorf("mac_factory: invalid mac")

// VerifyMAC verifies whether the given mac is a correct authentication code
// for the given data.
func (m *primitiveSet) VerifyMAC(mac, data []byte) error {
	// This also rejects raw MAC with size of 4 bytes or fewer. Those MACs are
	// clearly insecure, thus should be discouraged.
	prefixSize := tink.NonRawPrefixSize
	if len(mac) <= prefixSize {
		return errInvalidMAC
	}
	// try non raw keys
	prefix := mac[:prefixSize]
	macNoPrefix := mac[prefixSize:]
	entries, err := m.ps.EntriesForPrefix(string(prefix))
	if err == nil {
		for i := 0; i < len(entries); i++ {
			var p tink.MAC = (entries[i].Primitive).(tink.MAC)
			if err = p.VerifyMAC(macNoPrefix, data); err == nil {
				return nil
			}
		}
	}
	// try raw keys
	entries, err = m.ps.RawEntries()
	if err == nil {
		for i := 0; i < len(entries); i++ {
			var p tink.MAC = (entries[i].Primitive).(tink.MAC)
			if err = p.VerifyMAC(mac, data); err == nil {
				return nil
			}
		}
	}
	// nothing worked
	return errInvalidMAC
}
