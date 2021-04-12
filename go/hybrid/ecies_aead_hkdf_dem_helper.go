// Copyright 2021 Google LLC
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

package hybrid

import (
	"errors"
	"fmt"
	"strings"

	"github.com/golang/protobuf/proto"
	"github.com/google/tink/go/core/registry"
	"github.com/google/tink/go/hybrid/subtle"
	"github.com/google/tink/go/tink"
	ctrhmacpb "github.com/google/tink/go/proto/aes_ctr_hmac_aead_go_proto"
	gcmpb "github.com/google/tink/go/proto/aes_gcm_go_proto"
	sivpb "github.com/google/tink/go/proto/aes_siv_go_proto"
	tinkpb "github.com/google/tink/go/proto/tink_go_proto"
)

const (
	aesGCMTypeURL         = "type.googleapis.com/google.crypto.tink.AesGcmKey"
	aesCTRHMACAEADTypeURL = "type.googleapis.com/google.crypto.tink.AesCtrHmacAeadKey"
	aesSIVTypeURL         = "type.googleapis.com/google.crypto.tink.AesSivKey"
)

// eciesAEADHKDFDEMHelper generates AEAD or DeterministicAEAD primitives for the specified KeyTemplate and key material.
// in order to implement the EciesAEADHKDFDEMHelper interface.
type eciesAEADHKDFDEMHelper struct {
	demKeyURL        string
	keyData          []byte
	symmetricKeySize uint32
	aesCTRSize       uint32
}

var _ subtle.EciesAEADHKDFDEMHelper = (*eciesAEADHKDFDEMHelper)(nil)

// newRegisterECIESAEADHKDFDemHelper initializes and returns a RegisterECIESAEADHKDFDemHelper
func newRegisterECIESAEADHKDFDemHelper(k *tinkpb.KeyTemplate) (*eciesAEADHKDFDEMHelper, error) {
	var len uint32
	var aesCTRSize uint32
	var keyFormat []byte

	if strings.Compare(k.TypeUrl, aesGCMTypeURL) == 0 {
		gcmKeyFormat := new(gcmpb.AesGcmKeyFormat)
		var err error
		if err = proto.Unmarshal(k.Value, gcmKeyFormat); err != nil {
			return nil, err
		}
		len = gcmKeyFormat.KeySize
		keyFormat, err = proto.Marshal(gcmKeyFormat)
		if err != nil {
			return nil, fmt.Errorf("failed to serialize key format, error :%v", err)
		}
	} else if strings.Compare(k.TypeUrl, aesCTRHMACAEADTypeURL) == 0 {
		aeadKeyFormat := new(ctrhmacpb.AesCtrHmacAeadKeyFormat)
		var err error
		if err = proto.Unmarshal(k.Value, aeadKeyFormat); err != nil {
			return nil, err
		}
		if aeadKeyFormat.AesCtrKeyFormat == nil || aeadKeyFormat.HmacKeyFormat == nil {
			return nil, fmt.Errorf("failed to deserialize key format")
		}
		aesCTRSize = aeadKeyFormat.AesCtrKeyFormat.KeySize
		len = aesCTRSize + aeadKeyFormat.HmacKeyFormat.KeySize
		keyFormat, err = proto.Marshal(aeadKeyFormat)
		if err != nil {
			return nil, fmt.Errorf("failed to serialize key format, error :%v", err)
		}
	} else if strings.Compare(k.TypeUrl, aesSIVTypeURL) == 0 {
		daeadKeyFormat := new(sivpb.AesSivKeyFormat)
		var err error
		if err = proto.Unmarshal(k.Value, daeadKeyFormat); err != nil {
			return nil, err
		}
		len = daeadKeyFormat.KeySize
		keyFormat, err = proto.Marshal(daeadKeyFormat)
		if err != nil {
			return nil, fmt.Errorf("failed to serialize key format, error :%v", err)
		}
	} else {
		return nil, fmt.Errorf("unsupported AEAD DEM key type: %s", k.TypeUrl)
	}
	km, err := registry.GetKeyManager(k.TypeUrl)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch KeyManager, error: %v", err)
	}

	key, err := km.NewKey(keyFormat)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch key, error: %v", err)
	}
	sk, err := proto.Marshal(key)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize key, error: %v", err)
	}

	return &eciesAEADHKDFDEMHelper{
		demKeyURL:        k.TypeUrl,
		keyData:          sk,
		symmetricKeySize: len,
		aesCTRSize:       aesCTRSize,
	}, nil
}

// GetSymmetricKeySize returns the symmetric key size
func (r *eciesAEADHKDFDEMHelper) GetSymmetricKeySize() uint32 {
	return r.symmetricKeySize

}

// GetAEADOrDAEAD returns the AEAD or deterministic AEAD primitive from the DEM
func (r *eciesAEADHKDFDEMHelper) GetAEADOrDAEAD(symmetricKeyValue []byte) (interface{}, error) {
	var sk []byte
	if uint32(len(symmetricKeyValue)) != r.GetSymmetricKeySize() {
		return nil, errors.New("symmetric key has incorrect length")
	}
	if strings.Compare(r.demKeyURL, aesGCMTypeURL) == 0 {
		gcmKey := new(gcmpb.AesGcmKey)
		var err error
		if err := proto.Unmarshal(r.keyData, gcmKey); err != nil {
			return nil, err
		}
		gcmKey.KeyValue = symmetricKeyValue
		sk, err = proto.Marshal(gcmKey)
		if err != nil {
			return nil, fmt.Errorf("failed to serialize key, error: %v", err)
		}

	} else if strings.Compare(r.demKeyURL, aesCTRHMACAEADTypeURL) == 0 {
		aesCTR := new(ctrhmacpb.AesCtrHmacAeadKey)
		var err error
		if err := proto.Unmarshal(r.keyData, aesCTR); err != nil {
			return nil, err
		}
		aesCTR.AesCtrKey.KeyValue = symmetricKeyValue[:r.aesCTRSize]
		aesCTR.HmacKey.KeyValue = symmetricKeyValue[r.aesCTRSize:]
		sk, err = proto.Marshal(aesCTR)
		if err != nil {
			return nil, fmt.Errorf("failed to serialize key, error: %v", err)
		}

	} else if strings.Compare(r.demKeyURL, aesSIVTypeURL) == 0 {
		sivKey := new(sivpb.AesSivKey)
		var err error
		if err := proto.Unmarshal(r.keyData, sivKey); err != nil {
			return nil, err
		}
		sivKey.KeyValue = symmetricKeyValue
		sk, err = proto.Marshal(sivKey)
		if err != nil {
			return nil, fmt.Errorf("failed to serialize key, error: %v", err)
		}

	} else {
		return nil, fmt.Errorf("unsupported AEAD DEM key type: %s", r.demKeyURL)
	}

	p, err := registry.Primitive(r.demKeyURL, sk)
	if err != nil {
		return nil, err
	}
	switch p.(type) {
	case tink.AEAD, tink.DeterministicAEAD:
		return p, nil
	default:
		return nil, fmt.Errorf("Unexpected primitive type returned by the registry for the DEM: %T", p)
	}
}
