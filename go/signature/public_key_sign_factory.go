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

package signature

import (
	"fmt"
	"github.com/google/tink/go/tink/tink"
	tinkpb "github.com/google/tink/proto/tink_go_proto"
	"sync"
)

// PublicKeySignFactory allows obtaining a PublicKeySign primitive from a
// KeysetHandle.
var publicKeySignFactoryInstance *publicKeySignFactory
var publicKeySignFactoryOnce sync.Once

type publicKeySignFactory struct{}

// publicKeySignFactory creates an instance of publicKeySignFactory if there isn't
// and returns the instance.
func PublicKeySignFactory() *publicKeySignFactory {
	publicKeySignFactoryOnce.Do(func() {
		publicKeySignFactoryInstance = new(publicKeySignFactory)
	})
	return publicKeySignFactoryInstance
}

// GetPrimitive returns a PublicKeySign primitive from the given keyset handle.
func (f *publicKeySignFactory) GetPrimitive(handle *tink.KeysetHandle) (tink.PublicKeySign, error) {
	return f.GetPrimitiveWithCustomerManager(handle, nil /*keyManager*/)
}

// GetPrimitiveWithCustomerManager returns a PublicKeySign primitive from the given
// keyset handle and custom key manager.
func (f *publicKeySignFactory) GetPrimitiveWithCustomerManager(
	handle *tink.KeysetHandle, manager tink.KeyManager) (tink.PublicKeySign, error) {
	ps, err := tink.Registry().GetPrimitivesWithCustomManager(handle, manager)
	if err != nil {
		return nil, fmt.Errorf("public_key_sign_factory: cannot obtain primitive set: %s", err)
	}
	var ret tink.PublicKeySign = newPrimitiveSetPublicKeySign(ps)
	return ret, nil
}

// primitiveSetPublicKeySign is an PublicKeySign implementation that uses the
// underlying primitive set for signing.
type primitiveSetPublicKeySign struct {
	ps *tink.PrimitiveSet
}

// Asserts that primitiveSetPublicKeySign implements the PublicKeySign interface.
var _ tink.PublicKeySign = (*primitiveSetPublicKeySign)(nil)

// newPrimitiveSetPublicKeySign creates a new instance of primitiveSetPublicKeySign
func newPrimitiveSetPublicKeySign(ps *tink.PrimitiveSet) *primitiveSetPublicKeySign {
	ret := new(primitiveSetPublicKeySign)
	ret.ps = ps
	return ret
}

// Sign signs the given data and returns the signature concatenated with
// the identifier of the primary primitive.
func (s *primitiveSetPublicKeySign) Sign(data []byte) ([]byte, error) {
	primary := s.ps.Primary()
	var signer tink.PublicKeySign = (primary.Primitive()).(tink.PublicKeySign)
	var signedData []byte
	if primary.OutputPrefixType() == tinkpb.OutputPrefixType_LEGACY {
		signedData = append(signedData, data...)
		signedData = append(signedData, tink.LEGACY_START_BYTE)
	} else {
		signedData = data
	}
	signature, err := signer.Sign(signedData)
	if err != nil {
		return nil, err
	}
	var ret []byte
	ret = append(ret, primary.Identifier()...)
	ret = append(ret, signature...)
	return ret, nil
}
