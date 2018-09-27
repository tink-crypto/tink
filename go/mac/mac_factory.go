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

// GetPrimitive creates a Mac primitive from the given keyset handle.
func GetPrimitive(kh *tink.KeysetHandle) (tink.Mac, error) {
	return PrimitiveWithKeyManager(kh, nil /*keyManager*/)
}

// PrimitiveWithKeyManager creates a Mac primitive from the given keyset handle and a custom key
// manager.
func PrimitiveWithKeyManager(kh *tink.KeysetHandle, km tink.KeyManager) (tink.Mac, error) {
	ps, err := tink.PrimitivesWithKeyManager(kh, km)
	if err != nil {
		return nil, fmt.Errorf("mac_factory: cannot obtain primitive set: %s", err)
	}
	var mac tink.Mac = newPrimitiveSet(ps)
	return mac, nil
}

// primitiveSet is a MAC implementation that uses the underlying primitive set to compute and
// verify MACs.
type primitiveSet struct {
	ps *tink.PrimitiveSet
}

// Asserts that primitiveSet implements the Mac interface.
var _ tink.Mac = (*primitiveSet)(nil)

func newPrimitiveSet(ps *tink.PrimitiveSet) *primitiveSet {
	ret := new(primitiveSet)
	ret.ps = ps
	return ret
}

// ComputeMac calculates a MAC over the given data using the primary primitive
// and returns the concatenation of the primary's identifier and the calculated mac.
func (m *primitiveSet) ComputeMac(data []byte) ([]byte, error) {
	primary := m.ps.Primary
	var primitive tink.Mac = (primary.Primitive).(tink.Mac)
	mac, err := primitive.ComputeMac(data)
	if err != nil {
		return nil, err
	}
	var ret []byte
	ret = append(ret, primary.Prefix...)
	ret = append(ret, mac...)
	return ret, nil
}

var errInvalidMac = fmt.Errorf("mac_factory: invalid mac")

// VerifyMac verifies whether the given mac is a correct authentication code
// for the given data.
func (m *primitiveSet) VerifyMac(mac, data []byte) (bool, error) {
	// This also rejects raw MAC with size of 4 bytes or fewer. Those MACs are
	// clearly insecure, thus should be discouraged.
	prefixSize := tink.NonRawPrefixSize
	if len(mac) <= prefixSize {
		return false, errInvalidMac
	}
	// try non raw keys
	prefix := mac[:prefixSize]
	macNoPrefix := mac[prefixSize:]
	entries, err := m.ps.EntriesForPrefix(string(prefix))
	if err == nil {
		for i := 0; i < len(entries); i++ {
			var p tink.Mac = (entries[i].Primitive).(tink.Mac)
			valid, err := p.VerifyMac(macNoPrefix, data)
			if err == nil && valid {
				return true, nil
			}
		}
	}
	// try raw keys
	entries, err = m.ps.RawEntries()
	if err == nil {
		for i := 0; i < len(entries); i++ {
			var p tink.Mac = (entries[i].Primitive).(tink.Mac)
			valid, err := p.VerifyMac(mac, data)
			if err == nil && valid {
				return true, nil
			}
		}
	}
	// nothing worked
	return false, errInvalidMac
}
