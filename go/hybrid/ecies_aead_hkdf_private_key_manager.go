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
	"github.com/google/tink/go/keyset"
	subtle "github.com/google/tink/go/subtle/hybrid"
	eahpb "github.com/google/tink/proto/ecies_aead_hkdf_go_proto"
	tinkpb "github.com/google/tink/proto/tink_go_proto"
)

const (
	eciesAeadHkdfPrivateKeyKeyVersion = 0
	eciesAeadHkdfPrivateKeyTypeURL    = "type.googleapis.com/google.crypto.tink.EciesAeadHkdfPrivateKey"
)

// common errors
var errInvalidEciesAeadHkdfPrivateKeyKey = fmt.Errorf("ecies_aead_hkdf_private_key_manager: invalid key")
var errInvalidEciesAeadHkdfPrivateKeyKeyFormat = fmt.Errorf("ecies_aead_hkdf_private_key_manager: invalid key format")

// eciesAeadHkdfPrivateKeyKeyManager is an implementation of KeyManager interface.
// It generates new EciesAeadHkdfPrivateKeyKey keys and produces new instances of EciesAeadHkdfPrivateKey subtle.
type eciesAeadHkdfPrivateKeyKeyManager struct{}

// Assert that eciesAeadHkdfPrivateKeyKeyManager implements the KeyManager interface.
var _ registry.KeyManager = (*eciesAeadHkdfPrivateKeyKeyManager)(nil)

// newEciesAeadHkdfPrivateKeyKeyManager creates a new aesGcmKeyManager.
func newEciesAeadHkdfPrivateKeyKeyManager() *eciesAeadHkdfPrivateKeyKeyManager {
	return new(eciesAeadHkdfPrivateKeyKeyManager)
}

// Primitive creates an EciesAeadHkdfPrivateKey subtle for the given serialized EciesAeadHkdfPrivateKey proto.
func (km *eciesAeadHkdfPrivateKeyKeyManager) Primitive(serializedKey []byte) (interface{}, error) {
	if len(serializedKey) == 0 {
		return nil, errInvalidEciesAeadHkdfPrivateKeyKey
	}
	key := new(eahpb.EciesAeadHkdfPrivateKey)
	if err := proto.Unmarshal(serializedKey, key); err != nil {
		return nil, errInvalidEciesAeadHkdfPrivateKeyKey
	}
	if err := km.validateKey(key); err != nil {
		return nil, errInvalidEciesAeadHkdfPrivateKeyKey
	}
	curve, err := subtle.GetCurve(key.PublicKey.Params.KemParams.CurveType.String())
	if err != nil {
		return nil, err
	}
	pvt := subtle.GetECPrivateKey(curve, key.KeyValue)
	rDem, err := newRegisterEciesAeadHkdfDemHelper(key.PublicKey.Params.DemParams.AeadDem)
	if err != nil {
		return nil, err
	}
	salt := key.PublicKey.Params.KemParams.HkdfSalt
	hash := key.PublicKey.Params.KemParams.HkdfHashType.String()
	ptFormat := key.PublicKey.Params.EcPointFormat.String()
	return subtle.NewEciesAeadHkdfHybridDecrypt(pvt, salt, hash, ptFormat, rDem)
}

// NewKey creates a new key according to specification the given serialized EciesAeadHkdfPrivateKeyKeyFormat.
func (km *eciesAeadHkdfPrivateKeyKeyManager) NewKey(serializedKeyFormat []byte) (proto.Message, error) {
	if len(serializedKeyFormat) == 0 {
		return nil, errInvalidEciesAeadHkdfPrivateKeyKeyFormat
	}
	keyFormat := new(eahpb.EciesAeadHkdfKeyFormat)
	if err := proto.Unmarshal(serializedKeyFormat, keyFormat); err != nil {
		return nil, errInvalidEciesAeadHkdfPrivateKeyKeyFormat
	}
	if err := km.validateKeyFormat(keyFormat); err != nil {
		return nil, errInvalidEciesAeadHkdfPrivateKeyKeyFormat
	}
	curve, err := subtle.GetCurve(keyFormat.Params.KemParams.CurveType.String())
	pvt, err := subtle.GenerateECDHKeyPair(curve)
	if err != nil {
		return nil, err
	}

	return &eahpb.EciesAeadHkdfPrivateKey{
		Version:  eciesAeadHkdfPrivateKeyKeyVersion,
		KeyValue: pvt.D.Bytes(),
		PublicKey: &eahpb.EciesAeadHkdfPublicKey{
			Version: eciesAeadHkdfPrivateKeyKeyVersion,
			Params:  keyFormat.Params,
			X:       pvt.PublicKey.Point.X.Bytes(),
			Y:       pvt.PublicKey.Point.Y.Bytes(),
		},
	}, nil
}

// NewKeyData creates a new KeyData according to specification in the given serialized
// EciesAeadHkdfPrivateKeyKeyFormat.
// It should be used solely by the key management API.
func (km *eciesAeadHkdfPrivateKeyKeyManager) NewKeyData(serializedKeyFormat []byte) (*tinkpb.KeyData, error) {
	key, err := km.NewKey(serializedKeyFormat)
	if err != nil {
		return nil, err
	}
	serializedKey, err := proto.Marshal(key)
	if err != nil {
		return nil, err
	}
	return &tinkpb.KeyData{
		TypeUrl:         eciesAeadHkdfPrivateKeyTypeURL,
		Value:           serializedKey,
		KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PRIVATE,
	}, nil
}

// DoesSupport indicates if this key manager supports the given key type.
func (km *eciesAeadHkdfPrivateKeyKeyManager) DoesSupport(typeURL string) bool {
	return typeURL == eciesAeadHkdfPrivateKeyTypeURL
}

// TypeURL returns the key type of keys managed by this key manager.
func (km *eciesAeadHkdfPrivateKeyKeyManager) TypeURL() string {
	return eciesAeadHkdfPrivateKeyTypeURL
}

// validateKey validates the given ECDSAPrivateKey.
func (km *eciesAeadHkdfPrivateKeyKeyManager) validateKey(key *eahpb.EciesAeadHkdfPrivateKey) error {
	if err := keyset.ValidateKeyVersion(key.Version, eciesAeadHkdfPrivateKeyKeyVersion); err != nil {
		return fmt.Errorf("ecies_aead_hkdf_private_key_manager: invalid key: %s", err)
	}
	return checkEciesAeadHkdfParams(key.PublicKey.Params)
}

// validateKeyFormat validates the given ECDSAKeyFormat.
func (km *eciesAeadHkdfPrivateKeyKeyManager) validateKeyFormat(format *eahpb.EciesAeadHkdfKeyFormat) error {
	return checkEciesAeadHkdfParams(format.Params)
}

func checkEciesAeadHkdfParams(params *eahpb.EciesAeadHkdfParams) error {
	_, err := subtle.GetCurve(params.KemParams.CurveType.String())
	if err != nil {
		return err
	}
	if strings.Compare(params.KemParams.HkdfHashType.String(), "HashType_UNKNOWN_HASH") == 0 {
		return errors.New("hash unsupported for HMAC")
	}

	if strings.Compare(params.EcPointFormat.String(), "EcPointFormat_UNKNOWN_FORMAT") == 0 {
		return errors.New("unknown EC point format")
	}
	km, err := registry.GetKeyManager(params.DemParams.AeadDem.TypeUrl)
	if err != nil {
		return err
	}
	_, err = km.NewKeyData(params.DemParams.AeadDem.Value)
	if err != nil {
		return err
	}
	return nil
}
