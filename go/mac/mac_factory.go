// Copyright 2017 Google Inc.
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
package mac

import (
  "fmt"
  "sync"
  "github.com/google/tink/go/tink/tink"
)

// Factory provides methods that allow obtaining a Mac primitive from a KeysetHandle.
// They get primitives from the Registry.
//
// The returned primitive works with a keyset (rather than a single key).
// To compute a MAC tag, it uses the primary key in the keyset, and prepends
// to the tag a certain prefix associated with the primary key. To verify a tag,
// the primitive uses the prefix of the tag to efficiently select the
// right key in the set. If the keys associated with the prefix do not validate the tag,
// the primitive tries all keys with OutputPrefixType_RAW.
var factoryInstance *factory
var factoryOnce sync.Once
type factory struct {}

// factory creates an instance of factory if there isn't and returns the instance.
func Factory() *factory {
  factoryOnce.Do(func() {
    factoryInstance = new(factory)
  })
  return factoryInstance
}

// GetPrimitive creates a Mac primitive from the given keyset handle.
func (f *factory) GetPrimitive(handle *tink.KeysetHandle) (tink.Mac, error) {
  return f.GetPrimitiveWithCustomerManager(handle, nil /*keyManager*/)
}

// GetPrimitiveWithCustomerManager creates a Mac primitive from the given
// keyset handle and a custom key manager.
func (f *factory) GetPrimitiveWithCustomerManager(
    handle *tink.KeysetHandle, manager tink.KeyManager) (tink.Mac, error) {
  ps, err := tink.Registry().GetPrimitivesWithCustomManager(handle, manager)
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
  prefixSize := tink.NON_RAW_PREFIX_SIZE
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