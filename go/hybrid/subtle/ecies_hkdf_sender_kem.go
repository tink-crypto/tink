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

import "github.com/google/tink/go/subtle"

// KEMKey represents a KEM managed key.
type KEMKey struct {
	Kem, SymmetricKey []byte
}

// ECIESHKDFSenderKem represents HKDF-based ECIES-KEM (key encapsulation mechanism)
//for ECIES sender.
type ECIESHKDFSenderKem struct {
	recipientPublicKey *ECPublicKey
}

// GenerateKey a HDKF based KEM.
func (s *ECIESHKDFSenderKem) encapsulate(hashAlg string, salt []byte, info []byte, keySize uint32, pointFormat string) (*KEMKey, error) {

	pvt, err := GenerateECDHKeyPair(s.recipientPublicKey.Curve)
	if err != nil {
		return nil, err
	}
	pub := pvt.PublicKey
	secret, err := ComputeSharedSecret(&s.recipientPublicKey.Point, pvt)
	if err != nil {
		return nil, err
	}

	sdata, err := PointEncode(pub.Curve, pointFormat, pub.Point)
	if err != nil {
		return nil, err
	}
	i := append(sdata, secret...)

	sKey, err := subtle.ComputeHKDF(hashAlg, i, salt, info, keySize)
	if err != nil {
		return nil, err
	}

	return &KEMKey{
		Kem:          sdata,
		SymmetricKey: sKey,
	}, nil

}
