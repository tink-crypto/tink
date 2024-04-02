// Copyright 2019 Google LLC
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

package keyset

import (
	"errors"
	"fmt"

	"google.golang.org/protobuf/encoding/prototext"
	"google.golang.org/protobuf/proto"

	"github.com/google/tink/go/core/primitiveset"
	"github.com/google/tink/go/core/registry"
	"github.com/google/tink/go/internal/internalapi"
	"github.com/google/tink/go/internal/registryconfig"
	"github.com/google/tink/go/tink"
	tinkpb "github.com/google/tink/go/proto/tink_go_proto"
)

var errInvalidKeyset = fmt.Errorf("keyset.Handle: invalid keyset")

// Handle provides access to a Keyset protobuf, to limit the exposure of actual protocol
// buffers that hold sensitive key material.
type Handle struct {
	ks          *tinkpb.Keyset
	annotations map[string]string
}

func newWithOptions(ks *tinkpb.Keyset, opts ...Option) (*Handle, error) {
	h := &Handle{ks: ks}
	if err := applyOptions(h, opts...); err != nil {
		return nil, err
	}
	return h, nil
}

// NewHandle creates a keyset handle that contains a single fresh key generated according
// to the given KeyTemplate.
func NewHandle(kt *tinkpb.KeyTemplate) (*Handle, error) {
	manager := NewManager()
	keyID, err := manager.Add(kt)
	if err != nil {
		return nil, fmt.Errorf("keyset.Handle: cannot generate new keyset: %s", err)
	}
	err = manager.SetPrimary(keyID)
	if err != nil {
		return nil, fmt.Errorf("keyset.Handle: cannot set primary: %s", err)
	}
	handle, err := manager.Handle()
	if err != nil {
		return nil, fmt.Errorf("keyset.Handle: cannot get keyset handle: %s", err)
	}
	return handle, nil
}

// NewHandleWithNoSecrets creates a new instance of KeysetHandle using the given keyset which does
// not contain any secret key material.
func NewHandleWithNoSecrets(ks *tinkpb.Keyset) (*Handle, error) {
	if ks == nil {
		return nil, errors.New("keyset.Handle: nil keyset")
	}
	h := &Handle{ks: ks}
	if h.hasSecrets() {
		// If you need to do this, you have to use func insecurecleartextkeyset.Read() instead.
		return nil, errors.New("importing unencrypted secret key material is forbidden")
	}
	return h, nil
}

// Read tries to create a Handle from an encrypted keyset obtained via reader.
func Read(reader Reader, masterKey tink.AEAD) (*Handle, error) {
	return ReadWithAssociatedData(reader, masterKey, []byte{})
}

// ReadWithAssociatedData tries to create a Handle from an encrypted keyset obtained via reader using the provided associated data.
func ReadWithAssociatedData(reader Reader, masterKey tink.AEAD, associatedData []byte) (*Handle, error) {
	encryptedKeyset, err := reader.ReadEncrypted()
	if err != nil {
		return nil, err
	}
	ks, err := decrypt(encryptedKeyset, masterKey, associatedData)
	if err != nil {
		return nil, err
	}
	return &Handle{ks: ks}, nil
}

// ReadWithNoSecrets tries to create a keyset.Handle from a keyset obtained via reader.
func ReadWithNoSecrets(reader Reader) (*Handle, error) {
	ks, err := reader.Read()
	if err != nil {
		return nil, err
	}
	return NewHandleWithNoSecrets(ks)
}

// Public returns a Handle of the public keys if the managed keyset contains private keys.
func (h *Handle) Public() (*Handle, error) {
	privKeys := h.ks.Key
	pubKeys := make([]*tinkpb.Keyset_Key, len(privKeys))

	for i := 0; i < len(privKeys); i++ {
		if privKeys[i] == nil || privKeys[i].KeyData == nil {
			return nil, errInvalidKeyset
		}
		privKeyData := privKeys[i].KeyData
		pubKeyData, err := publicKeyData(privKeyData)
		if err != nil {
			return nil, fmt.Errorf("keyset.Handle: %s", err)
		}
		pubKeys[i] = &tinkpb.Keyset_Key{
			KeyData:          pubKeyData,
			Status:           privKeys[i].Status,
			KeyId:            privKeys[i].KeyId,
			OutputPrefixType: privKeys[i].OutputPrefixType,
		}
	}
	ks := &tinkpb.Keyset{
		PrimaryKeyId: h.ks.PrimaryKeyId,
		Key:          pubKeys,
	}
	return &Handle{ks: ks}, nil
}

// String returns a string representation of the managed keyset.
// The result does not contain any sensitive key material.
func (h *Handle) String() string {
	c, err := prototext.MarshalOptions{}.Marshal(getKeysetInfo(h.ks))
	if err != nil {
		return ""
	}
	return string(c)
}

// KeysetInfo returns KeysetInfo representation of the managed keyset.
// The result does not contain any sensitive key material.
func (h *Handle) KeysetInfo() *tinkpb.KeysetInfo {
	return getKeysetInfo(h.ks)
}

// Write encrypts and writes the enclosing keyset.
func (h *Handle) Write(writer Writer, masterKey tink.AEAD) error {
	return h.WriteWithAssociatedData(writer, masterKey, []byte{})
}

// WriteWithAssociatedData encrypts and writes the enclosing keyset using the provided associated data.
func (h *Handle) WriteWithAssociatedData(writer Writer, masterKey tink.AEAD, associatedData []byte) error {
	encrypted, err := encrypt(h.ks, masterKey, associatedData)
	if err != nil {
		return err
	}
	return writer.WriteEncrypted(encrypted)
}

// WriteWithNoSecrets exports the keyset in h to the given Writer w returning an error if the keyset
// contains secret key material.
func (h *Handle) WriteWithNoSecrets(w Writer) error {
	if h.hasSecrets() {
		return errors.New("exporting unencrypted secret key material is forbidden")
	}

	return w.Write(h.ks)
}

// Config defines methods in the config.Config concrete type that are used by keyset.Handle.
// The config.Config concrete type is not used directly due to circular dependencies.
type Config interface {
	PrimitiveFromKeyData(keyData *tinkpb.KeyData, _ internalapi.Token) (any, error)
}
type primitiveOptions struct {
	config Config
}

// PrimitivesOption is used to configure Primitives(...).
type PrimitivesOption func(*primitiveOptions) error

// WithConfig sets the configuration used to create primitives via Primitives().
// If this option is omitted, default to using the global registry.
func WithConfig(c Config) PrimitivesOption {
	return func(args *primitiveOptions) error {
		if args.config != nil {
			return fmt.Errorf("configuration has already been set")
		}
		args.config = c
		return nil
	}
}

// Primitives creates a set of primitives corresponding to the keys with
// status=ENABLED in the keyset of the given keyset handle. It uses the
// key managers that are present in the global Registry or in the Config,
// should it be provided. It assumes that all the needed key managers are
// present. Keys with status!=ENABLED are skipped.
//
// An example usage where a custom config is provided:
//
//	ps, err := h.Primitives(WithConfig(config.V0()))
//
// The returned set is usually later "wrapped" into a class that implements
// the corresponding Primitive-interface.
func (h *Handle) Primitives(opts ...PrimitivesOption) (*primitiveset.PrimitiveSet, error) {
	p, err := h.primitives(nil, opts...)
	if err != nil {
		return nil, fmt.Errorf("handle.Primitives: %v", err)
	}
	return p, nil
}

// PrimitivesWithKeyManager creates a set of primitives corresponding to
// the keys with status=ENABLED in the keyset of the given keysetHandle, using
// the given key manager (instead of registered key managers) for keys supported
// by it.  Keys not supported by the key manager are handled by matching registered
// key managers (if present), and keys with status!=ENABLED are skipped.
//
// This enables custom treatment of keys, for example providing extra context
// (e.g. credentials for accessing keys managed by a KMS), or gathering custom
// monitoring/profiling information.
//
// The returned set is usually later "wrapped" into a class that implements
// the corresponding Primitive-interface.
func (h *Handle) PrimitivesWithKeyManager(km registry.KeyManager) (*primitiveset.PrimitiveSet, error) {
	p, err := h.primitives(km)
	if err != nil {
		return nil, fmt.Errorf("handle.PrimitivesWithKeyManager: %v", err)
	}
	return p, nil
}

func (h *Handle) primitives(km registry.KeyManager, opts ...PrimitivesOption) (*primitiveset.PrimitiveSet, error) {
	args := new(primitiveOptions)
	for _, opt := range opts {
		if err := opt(args); err != nil {
			return nil, fmt.Errorf("failed to process primitiveOptions: %v", err)
		}
	}
	config := args.config
	if config == nil {
		config = &registryconfig.RegistryConfig{}
	}

	if err := Validate(h.ks); err != nil {
		return nil, fmt.Errorf("invalid keyset: %v", err)
	}
	primitiveSet := primitiveset.New()
	primitiveSet.Annotations = h.annotations
	for _, key := range h.ks.Key {
		if key.Status != tinkpb.KeyStatusType_ENABLED {
			continue
		}
		var primitive any
		var err error
		if km != nil && km.DoesSupport(key.KeyData.TypeUrl) {
			primitive, err = km.Primitive(key.KeyData.Value)
		} else {
			primitive, err = config.PrimitiveFromKeyData(key.KeyData, internalapi.Token{})
		}
		if err != nil {
			return nil, fmt.Errorf("cannot get primitive from key: %v", err)
		}
		entry, err := primitiveSet.Add(primitive, key)
		if err != nil {
			return nil, fmt.Errorf("cannot add primitive: %v", err)
		}
		if key.KeyId == h.ks.PrimaryKeyId {
			primitiveSet.Primary = entry
		}
	}
	return primitiveSet, nil
}

// hasSecrets returns true if the keyset handle contains key material considered secret. This
// includes symmetric keys, private keys of asymmetric crypto systems, and keys of an unknown type.
func (h *Handle) hasSecrets() bool {
	for _, k := range h.ks.Key {
		if k == nil || k.KeyData == nil {
			continue
		}
		if k.KeyData.KeyMaterialType == tinkpb.KeyData_UNKNOWN_KEYMATERIAL {
			return true
		}
		if k.KeyData.KeyMaterialType == tinkpb.KeyData_ASYMMETRIC_PRIVATE {
			return true
		}
		if k.KeyData.KeyMaterialType == tinkpb.KeyData_SYMMETRIC {
			return true
		}
	}
	return false
}

func publicKeyData(privKeyData *tinkpb.KeyData) (*tinkpb.KeyData, error) {
	if privKeyData.KeyMaterialType != tinkpb.KeyData_ASYMMETRIC_PRIVATE {
		return nil, fmt.Errorf("keyset.Handle: keyset contains a non-private key")
	}
	km, err := registry.GetKeyManager(privKeyData.TypeUrl)
	if err != nil {
		return nil, err
	}
	pkm, ok := km.(registry.PrivateKeyManager)
	if !ok {
		return nil, fmt.Errorf("keyset.Handle: %s does not belong to a PrivateKeyManager", privKeyData.TypeUrl)
	}
	return pkm.PublicKeyData(privKeyData.Value)
}

func decrypt(encryptedKeyset *tinkpb.EncryptedKeyset, masterKey tink.AEAD, associatedData []byte) (*tinkpb.Keyset, error) {
	if encryptedKeyset == nil || masterKey == nil {
		return nil, fmt.Errorf("keyset.Handle: invalid encrypted keyset")
	}
	decrypted, err := masterKey.Decrypt(encryptedKeyset.EncryptedKeyset, associatedData)
	if err != nil {
		return nil, fmt.Errorf("keyset.Handle: decryption failed: %s", err)
	}
	keyset := new(tinkpb.Keyset)
	if err := proto.Unmarshal(decrypted, keyset); err != nil {
		return nil, errInvalidKeyset
	}
	return keyset, nil
}

func encrypt(keyset *tinkpb.Keyset, masterKey tink.AEAD, associatedData []byte) (*tinkpb.EncryptedKeyset, error) {
	serializedKeyset, err := proto.Marshal(keyset)
	if err != nil {
		return nil, errInvalidKeyset
	}
	encrypted, err := masterKey.Encrypt(serializedKeyset, associatedData)
	if err != nil {
		return nil, fmt.Errorf("keyset.Handle: encrypted failed: %s", err)
	}
	// get keyset info
	encryptedKeyset := &tinkpb.EncryptedKeyset{
		EncryptedKeyset: encrypted,
		KeysetInfo:      getKeysetInfo(keyset),
	}
	return encryptedKeyset, nil
}

// getKeysetInfo returns a KeysetInfo from a Keyset protobuf.
func getKeysetInfo(keyset *tinkpb.Keyset) *tinkpb.KeysetInfo {
	if keyset == nil {
		panic("keyset.Handle: keyset must be non nil")
	}
	nKey := len(keyset.Key)
	keyInfos := make([]*tinkpb.KeysetInfo_KeyInfo, nKey)
	for i, key := range keyset.Key {
		keyInfos[i] = getKeyInfo(key)
	}
	return &tinkpb.KeysetInfo{
		PrimaryKeyId: keyset.PrimaryKeyId,
		KeyInfo:      keyInfos,
	}
}

// getKeyInfo returns a KeyInfo from a Key protobuf.
func getKeyInfo(key *tinkpb.Keyset_Key) *tinkpb.KeysetInfo_KeyInfo {
	return &tinkpb.KeysetInfo_KeyInfo{
		TypeUrl:          key.KeyData.TypeUrl,
		Status:           key.Status,
		KeyId:            key.KeyId,
		OutputPrefixType: key.OutputPrefixType,
	}
}
