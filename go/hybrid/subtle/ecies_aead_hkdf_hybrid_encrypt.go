// Copyright 2020 Google LLC
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

package subtle

import (
	"bytes"
	"errors"

	"github.com/google/tink/go/tink"
)

// ECIESAEADHKDFHybridEncrypt is an instance of ECIES encryption with HKDF-KEM (key encapsulation mechanism)
// and AEAD-DEM (data encapsulation mechanism).
type ECIESAEADHKDFHybridEncrypt struct {
	publicKey    *ECPublicKey
	hkdfSalt     []byte
	hkdfHMACAlgo string
	pointFormat  string
	demHelper    EciesAEADHKDFDEMHelper
}

// NewECIESAEADHKDFHybridEncrypt returns ECIES encryption construct with HKDF-KEM (key encapsulation mechanism)
// and AEAD-DEM (data encapsulation mechanism).
func NewECIESAEADHKDFHybridEncrypt(pub *ECPublicKey, hkdfSalt []byte, hkdfHMACAlgo string, ptFormat string, demHelper EciesAEADHKDFDEMHelper) (*ECIESAEADHKDFHybridEncrypt, error) {
	c, err := GetCurve(pub.Curve.Params().Name)
	if err != nil {
		return nil, err
	}
	return &ECIESAEADHKDFHybridEncrypt{
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
func (e *ECIESAEADHKDFHybridEncrypt) Encrypt(plaintext, contextInfo []byte) ([]byte, error) {
	var b bytes.Buffer
	sKem := &ECIESHKDFSenderKem{
		recipientPublicKey: e.publicKey,
	}
	kemKey, err := sKem.encapsulate(e.hkdfHMACAlgo, e.hkdfSalt, contextInfo, e.demHelper.GetSymmetricKeySize(), e.pointFormat)
	if err != nil {
		return nil, err
	}
	prim, err := e.demHelper.GetAEADOrDAEAD(kemKey.SymmetricKey)
	if err != nil {
		return nil, err
	}
	var ct []byte
	switch a := prim.(type) {
	case tink.AEAD:
		ct, err = a.Encrypt(plaintext, []byte{})
	case tink.DeterministicAEAD:
		ct, err = a.EncryptDeterministically(plaintext, []byte{})
	default:
		err = errors.New("Internal error: unexpected primitive type")
	}
	if err != nil {
		return nil, err
	}
	b.Write(kemKey.Kem)
	b.Write(ct)
	return b.Bytes(), nil
}
