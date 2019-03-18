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
	subtle "github.com/google/tink/go/subtle/hybrid"
	"github.com/google/tink/go/tink"
	ctrhmacpb "github.com/google/tink/proto/aes_ctr_hmac_aead_go_proto"
	gcmpb "github.com/google/tink/proto/aes_gcm_go_proto"
	tinkpb "github.com/google/tink/proto/tink_go_proto"
)

const (
	aesGCMTypeURL         = "type.googleapis.com/google.crypto.tink.AesGcmKey"
	aesCTRHMACAEADTypeURL = "type.googleapis.com/google.crypto.tink.AesCtrHmacAeadKey"
)

// registerECIESAEADHKDFDemHelper registers a DEM helper.
type registerECIESAEADHKDFDemHelper struct {
	demKeyURL        string
	keyData          []byte
	symmetricKeySize uint32
	aesCTRSize       uint32
}

var _ subtle.EciesAEADHKDFDEMHelper = (*registerECIESAEADHKDFDemHelper)(nil)

// newRegisterECIESAEADHKDFDemHelper initializes and returns a RegisterECIESAEADHKDFDemHelper
func newRegisterECIESAEADHKDFDemHelper(k *tinkpb.KeyTemplate) (*registerECIESAEADHKDFDemHelper, error) {
	var len uint32
	var a uint32
	var skf []byte
	var err error
	u := k.TypeUrl

	if strings.Compare(u, aesGCMTypeURL) == 0 {
		gcmKeyFormat := new(gcmpb.AesGcmKeyFormat)
		if err := proto.Unmarshal(k.Value, gcmKeyFormat); err != nil {
			return nil, err
		}
		len = gcmKeyFormat.KeySize
		a = 0
		skf, err = proto.Marshal(gcmKeyFormat)
		if err != nil {
			return nil, fmt.Errorf("failed to serialize key format, error :%v", err)
		}
	} else if strings.Compare(u, aesCTRHMACAEADTypeURL) == 0 {
		aeadKeyFormat := new(ctrhmacpb.AesCtrHmacAeadKeyFormat)
		if err := proto.Unmarshal(k.Value, aeadKeyFormat); err != nil {
			return nil, err
		}
		if aeadKeyFormat.AesCtrKeyFormat == nil || aeadKeyFormat.HmacKeyFormat == nil {
			return nil, fmt.Errorf("failed to deserialize key format")
		}
		a = aeadKeyFormat.AesCtrKeyFormat.KeySize
		len = a + aeadKeyFormat.HmacKeyFormat.KeySize
		skf, err = proto.Marshal(aeadKeyFormat)
		if err != nil {
			return nil, fmt.Errorf("failed to serialize key format, error :%v", err)
		}
	} else {
		return nil, fmt.Errorf("unsupported AEAD DEM key type: %s", u)
	}
	km, err := registry.GetKeyManager(k.TypeUrl)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch KeyManager, error: %v", err)
	}

	key, err := km.NewKey(skf)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch key, error: %v", err)
	}
	sk, err := proto.Marshal(key)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize key, error: %v", err)
	}

	return &registerECIESAEADHKDFDemHelper{
		demKeyURL:        u,
		keyData:          sk,
		symmetricKeySize: len,
		aesCTRSize:       a,
	}, nil
}

// GetSymmetricKeySize returns the symmetric key size
func (r *registerECIESAEADHKDFDemHelper) GetSymmetricKeySize() uint32 {
	return r.symmetricKeySize

}

// GetAEAD returns the AEAD primitive from the DEM
func (r *registerECIESAEADHKDFDemHelper) GetAEAD(symmetricKeyValue []byte) (tink.AEAD, error) {
	var sk []byte
	var pErr error
	if uint32(len(symmetricKeyValue)) != r.GetSymmetricKeySize() {
		return nil, errors.New("symmetric key has incorrect length")
	}
	if strings.Compare(r.demKeyURL, aesGCMTypeURL) == 0 {
		gcmKey := new(gcmpb.AesGcmKey)
		if err := proto.Unmarshal(r.keyData, gcmKey); err != nil {
			return nil, err
		}
		gcmKey.KeyValue = symmetricKeyValue
		sk, pErr = proto.Marshal(gcmKey)
		if pErr != nil {
			return nil, fmt.Errorf("failed to serialize key, error: %v", pErr)
		}

	} else if strings.Compare(r.demKeyURL, aesCTRHMACAEADTypeURL) == 0 {
		aesCTR := new(ctrhmacpb.AesCtrHmacAeadKey)
		if err := proto.Unmarshal(r.keyData, aesCTR); err != nil {
			return nil, err
		}
		aesCTR.AesCtrKey.KeyValue = symmetricKeyValue[:r.aesCTRSize]
		aesCTR.HmacKey.KeyValue = symmetricKeyValue[r.aesCTRSize:]
		sk, pErr = proto.Marshal(aesCTR)
		if pErr != nil {
			return nil, fmt.Errorf("failed to serialize key, error: %v", pErr)
		}

	} else {
		return nil, fmt.Errorf("unsupported AEAD DEM key type: %s", r.demKeyURL)
	}

	p, err := registry.Primitive(r.demKeyURL, sk)
	if err != nil {
		return nil, err
	}
	g := p.(tink.AEAD)
	return g, nil
}
