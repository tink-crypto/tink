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

package hybrid

import (
	"bytes"

	"github.com/google/tink/go/tink"
)

// EciesAeadHkdfHybridEncrypt is an instance of ECIES encryption with HKDF-KEM (key encapsulation mechanism)
// and AEAD-DEM (data encapsulation mechanism).
type EciesAeadHkdfHybridEncrypt struct {
	publicKey    *ECPublicKey
	hkdfSalt     []byte
	hkdfHMACAlgo string
	pointFormat  string
	demHelper    EciesAeadHkdfDemHelper
}

var _ tink.HybridEncrypt = (*EciesAeadHkdfHybridEncrypt)(nil)

// NewEciesAeadHkdfHybridEncrypt returns ECIES encryption construct with HKDF-KEM (key encapsulation mechanism)
// and AEAD-DEM (data encapsulation mechanism).
func NewEciesAeadHkdfHybridEncrypt(pub *ECPublicKey, hkdfSalt []byte, hkdfHMACAlgo string, ptFormat string, demHelper EciesAeadHkdfDemHelper) (*EciesAeadHkdfHybridEncrypt, error) {
	c, err := getCurve(pub.Curve.Params().Name)
	if err != nil {
		return nil, err
	}
	return &EciesAeadHkdfHybridEncrypt{
		publicKey: &ECPublicKey{
			Curve: c,
			Point: pub.Point,
		},
		hkdfSalt:     hkdfSalt,
		hkdfHMACAlgo: hkdfHMACAlgo,
		pointFormat:  ptFormat,
		demHelper:    demHelper,
	}, nil
}

// Encrypt is used to encrypt using ECIES with a HKDF-KEM and AEAD-DEM mechanisms.
func (e *EciesAeadHkdfHybridEncrypt) Encrypt(plaintext, contextInfo []byte) ([]byte, error) {
	var b bytes.Buffer
	sKem := &ECIESHKDFSenderKem{
		recipientPublicKey: e.publicKey,
	}
	kemKey, err := sKem.encapsulate(e.hkdfHMACAlgo, e.hkdfSalt, contextInfo, e.demHelper.getSymmetricKeySize(), e.pointFormat)
	if err != nil {
		return nil, err
	}
	aead, err := e.demHelper.getAead(kemKey.SymmetricKey)
	if err != nil {
		return nil, err
	}
	ct, err := aead.Encrypt(plaintext, []byte{})
	if err != nil {
		return nil, err
	}
	b.Write(kemKey.Kem)
	b.Write(ct)
	return b.Bytes(), nil
}
