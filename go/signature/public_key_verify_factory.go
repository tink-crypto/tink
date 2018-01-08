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

// publicKeyVerifyFactory allows obtaining a PublicKeySign primitive from a
// KeysetHandle.
var publicKeyVerifyFactoryInstance *publicKeyVerifyFactory
var publicKeyVerifyFactoryOnce sync.Once

type publicKeyVerifyFactory struct{}

// PublicKeyVerifyFactory creates an instance of publicKeyVerifyFactory if there isn't
// and returns the instance.
func PublicKeyVerifyFactory() *publicKeyVerifyFactory {
	publicKeyVerifyFactoryOnce.Do(func() {
		publicKeyVerifyFactoryInstance = new(publicKeyVerifyFactory)
	})
	return publicKeyVerifyFactoryInstance
}

// GetPrimitive returns a PublicKeyVerify primitive from the given keyset handle.
func (f *publicKeyVerifyFactory) GetPrimitive(handle *tink.KeysetHandle) (tink.PublicKeyVerify, error) {
	return f.GetPrimitiveWithCustomerManager(handle, nil /*keyManager*/)
}

// GetPrimitiveWithCustomerManager returns a PublicKeyVerify primitive from the given
// keyset handle and custom key manager.
func (f *publicKeyVerifyFactory) GetPrimitiveWithCustomerManager(
	handle *tink.KeysetHandle, manager tink.KeyManager) (tink.PublicKeyVerify, error) {
	ps, err := tink.Registry().GetPrimitivesWithCustomManager(handle, manager)
	if err != nil {
		return nil, fmt.Errorf("public_key_verify_factory: cannot obtain primitive set: %s", err)
	}
	var ret = newprimitiveSetPublicKeyVerify(ps)
	return ret, nil
}

// primitiveSetPublicKeyVerify is an PublicKeySign implementation that uses the
// underlying primitive set for signing.
type primitiveSetPublicKeyVerify struct {
	ps *tink.PrimitiveSet
}

// Asserts that primitiveSetPublicKeyVerify implements the PublicKeyVerify interface.
var _ tink.PublicKeyVerify = (*primitiveSetPublicKeyVerify)(nil)

// newprimitiveSetPublicKeyVerify creates a new instance of primitiveSetPublicKeyVerify
func newprimitiveSetPublicKeyVerify(ps *tink.PrimitiveSet) *primitiveSetPublicKeyVerify {
	ret := new(primitiveSetPublicKeyVerify)
	ret.ps = ps
	return ret
}

var errInvalidSignature = fmt.Errorf("public_key_verify_factory: invalid signature")

// Verify checks whether the given signature is a valid signature of the given data.
func (v *primitiveSetPublicKeyVerify) Verify(signature []byte, data []byte) error {
	if len(signature) < tink.NON_RAW_PREFIX_SIZE {
		return errInvalidSignature
	}
	// try non-raw keys
	prefix := signature[:tink.NON_RAW_PREFIX_SIZE]
	signatureNoPrefix := signature[tink.NON_RAW_PREFIX_SIZE:]
	entries, err := v.ps.GetPrimitivesWithByteIdentifier(prefix)
	if err == nil {
		for i := 0; i < len(entries); i++ {
			var signedData []byte
			if entries[i].OutputPrefixType() == tinkpb.OutputPrefixType_LEGACY {
				signedData = append(signedData, data...)
				signedData = append(signedData, tink.LEGACY_START_BYTE)
			} else {
				signedData = data
			}
			var verifier = (entries[i].Primitive()).(tink.PublicKeyVerify)
			if err := verifier.Verify(signatureNoPrefix, signedData); err == nil {
				return nil
			}
		}
	}
	// try raw keys
	entries, err = v.ps.GetRawPrimitives()
	if err == nil {
		for i := 0; i < len(entries); i++ {
			var verifier = (entries[i].Primitive()).(tink.PublicKeyVerify)
			if err := verifier.Verify(signature, data); err == nil {
				return nil
			}
		}
	}
	return errInvalidSignature
}
