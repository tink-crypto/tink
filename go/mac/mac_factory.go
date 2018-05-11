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
func GetPrimitive(handle *tink.KeysetHandle) (tink.Mac, error) {
	return GetPrimitiveWithCustomerManager(handle, nil /*keyManager*/)
}

// GetPrimitiveWithCustomerManager creates a Mac primitive from the given
// keyset handle and a custom key manager.
func GetPrimitiveWithCustomerManager(
	handle *tink.KeysetHandle, manager tink.KeyManager) (tink.Mac, error) {
	ps, err := tink.GetPrimitivesWithCustomManager(handle, manager)
	if err != nil {
		return nil, fmt.Errorf("mac_factory: cannot obtain primitive set: %s", err)
	}
	var mac tink.Mac = newPrimitiveSetMac(ps)
	return mac, nil
}

// primitiveSetMac is a MAC implementation that uses the underlying primitive set to compute and
// verify MACs.
type primitiveSetMac struct {
	ps *tink.PrimitiveSet
}

// Asserts that primitiveSetMac implements the Mac interface.
var _ tink.Mac = (*primitiveSetMac)(nil)

// newPrimitiveSetMac creates a new instance of primitiveSetMac using the given
// primitive set.
func newPrimitiveSetMac(ps *tink.PrimitiveSet) *primitiveSetMac {
	ret := new(primitiveSetMac)
	ret.ps = ps
	return ret
}

// ComputeMac calculates a MAC over the given data using the primary primitive
// and returns the concatenation of the primary's identifier and the calculated mac.
func (m *primitiveSetMac) ComputeMac(data []byte) ([]byte, error) {
	primary := m.ps.Primary()
	var primitive tink.Mac = (primary.Primitive()).(tink.Mac)
	mac, err := primitive.ComputeMac(data)
	if err != nil {
		return nil, err
	}
	var ret []byte
	ret = append(ret, primary.Identifier()...)
	ret = append(ret, mac...)
	return ret, nil
}

var errInvalidMac = fmt.Errorf("mac_factory: invalid mac")

// VerifyMac verifies whether the given mac is a correct authentication code
// for the given data.
func (m *primitiveSetMac) VerifyMac(mac []byte, data []byte) (bool, error) {
	// This also rejects raw MAC with size of 4 bytes or fewer. Those MACs are
	// clearly insecure, thus should be discouraged.
	prefixSize := tink.NonRawPrefixSize
	if len(mac) <= prefixSize {
		return false, errInvalidMac
	}
	// try non raw keys
	prefix := mac[:prefixSize]
	macNoPrefix := mac[prefixSize:]
	entries, err := m.ps.GetPrimitivesWithByteIdentifier(prefix)
	if err == nil {
		for i := 0; i < len(entries); i++ {
			var p tink.Mac = (entries[i].Primitive()).(tink.Mac)
			valid, err := p.VerifyMac(macNoPrefix, data)
			if err == nil && valid {
				return true, nil
			}
		}
	}
	// try raw keys
	entries, err = m.ps.GetRawPrimitives()
	if err == nil {
		for i := 0; i < len(entries); i++ {
			var p tink.Mac = (entries[i].Primitive()).(tink.Mac)
			valid, err := p.VerifyMac(mac, data)
			if err == nil && valid {
				return true, nil
			}
		}
	}
	// nothing worked
	return false, errInvalidMac
}
