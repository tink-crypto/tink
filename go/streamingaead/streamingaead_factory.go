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

package streamingaead

import (
	"fmt"
	"io"

	"github.com/google/tink/go/core/primitiveset"
	"github.com/google/tink/go/core/registry"
	"github.com/google/tink/go/keyset"
	"github.com/google/tink/go/tink"
)

// New returns a StreamingAEAD primitive from the given keyset handle.
func New(h *keyset.Handle) (tink.StreamingAEAD, error) {
	return NewWithKeyManager(h, nil /*keyManager*/)
}

// NewWithKeyManager returns a StreamingAEAD primitive from the given keyset handle and custom key manager.
func NewWithKeyManager(h *keyset.Handle, km registry.KeyManager) (tink.StreamingAEAD, error) {
	ps, err := h.PrimitivesWithKeyManager(km)
	if err != nil {
		return nil, fmt.Errorf("streamingaead_factory: cannot obtain primitive set: %s", err)
	}
	ret := new(primitiveSet)
	ret.ps = ps
	return tink.StreamingAEAD(ret), nil
}

// primitiveSet is an StreamingAEAD implementation that uses the underlying primitive set
// for deterministic encryption and decryption.
type primitiveSet struct {
	ps *primitiveset.PrimitiveSet
}

// Asserts that primitiveSet implements the StreamingAEAD interface.
var _ tink.StreamingAEAD = (*primitiveSet)(nil)

// NewEncryptingWriter returns a wrapper around underlying io.Writer, such that any write-operation
// via the wrapper results in AEAD-encryption of the written data, using aad
// as associated authenticated data. The associated data is not included in the ciphertext
// and has to be passed in as parameter for decryption.
func (s *primitiveSet) NewEncryptingWriter(w io.Writer, aad []byte) (io.WriteCloser, error) {
	primary := s.ps.Primary
	p := (primary.Primitive).(tink.StreamingAEAD)
	return p.NewEncryptingWriter(w, aad)
}

// NewDecryptingReader returns a wrapper around underlying io.Reader, such that any read-operation
// via the wrapper results in AEAD-decryption of the underlying ciphertext,
// using aad as associated authenticated data.
func (s *primitiveSet) NewDecryptingReader(r io.Reader, aad []byte) (io.Reader, error) {
	return &decryptReader{
		ps:  s,
		cr:  r,
		aad: aad,
	}, nil
}
