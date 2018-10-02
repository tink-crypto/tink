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

	"github.com/google/tink/go/tink"
	tinkpb "github.com/google/tink/proto/tink_go_proto"
)

// NewSigner returns a Signer primitive from the given keyset handle.
func NewSigner(kh *tink.KeysetHandle) (tink.Signer, error) {
	return NewSignerWithKeyManager(kh, nil /*keyManager*/)
}

// NewSignerWithKeyManager returns a Signer primitive from the given keyset handle and custom
// key manager.
func NewSignerWithKeyManager(kh *tink.KeysetHandle, km tink.KeyManager) (tink.Signer, error) {
	ps, err := tink.PrimitivesWithKeyManager(kh, km)
	if err != nil {
		return nil, fmt.Errorf("public_key_sign_factory: cannot obtain primitive set: %s", err)
	}
	var ret tink.Signer = newSignerSet(ps)
	return ret, nil
}

// signerSet is an Signer implementation that uses the underlying primitive set for signing.
type signerSet struct {
	ps *tink.PrimitiveSet
}

// Asserts that signerSet implements the Signer interface.
var _ tink.Signer = (*signerSet)(nil)

func newSignerSet(ps *tink.PrimitiveSet) *signerSet {
	ret := new(signerSet)
	ret.ps = ps
	return ret
}

// Sign signs the given data and returns the signature concatenated with the identifier of the
// primary primitive.
func (s *signerSet) Sign(data []byte) ([]byte, error) {
	primary := s.ps.Primary
	var signer tink.Signer = (primary.Primitive).(tink.Signer)
	var signedData []byte
	if primary.PrefixType == tinkpb.OutputPrefixType_LEGACY {
		signedData = append(signedData, data...)
		signedData = append(signedData, tink.LegacyStartByte)
	} else {
		signedData = data
	}
	signature, err := signer.Sign(signedData)
	if err != nil {
		return nil, err
	}
	var ret []byte
	ret = append(ret, primary.Prefix...)
	ret = append(ret, signature...)
	return ret, nil
}
