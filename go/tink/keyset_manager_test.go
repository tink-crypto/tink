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

package tink_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/google/tink/go/aead"
	"github.com/google/tink/go/mac"
	"github.com/google/tink/go/testutil"
	"github.com/google/tink/go/tink"
	tinkpb "github.com/google/tink/proto/tink_go_proto"
)

func setupKeysetManagerTest() {
	_, err := mac.RegisterStandardKeyTypes()
	if err != nil {
		panic(fmt.Sprintf("cannot register mac key types: %s", err))
	}
	_, err = aead.RegisterStandardKeyTypes()
	if err != nil {
		panic(fmt.Sprintf("cannot register aead key types: %s", err))
	}
}

func TestKeysetManagerBasic(t *testing.T) {
	setupKeysetManagerTest()

	manager := tink.NewKeysetManager(nil, nil, nil)
	err := manager.Rotate()
	if err == nil || !strings.Contains(err.Error(), "need key template") {
		t.Errorf("expect an error when key template is nil")
	}
	// Create a keyset that contains a single HmacKey.
	template := mac.HmacSha256Tag128KeyTemplate()
	manager = tink.NewKeysetManager(template, nil, nil)
	err = manager.Rotate()
	if err != nil {
		t.Errorf("cannot rotate when key template is available: %s", err)
	}
	keyset := manager.Keyset()
	if len(keyset.Key) != 1 {
		t.Errorf("expect the number of keys in the keyset is 1")
	}
	if keyset.Key[0].KeyId != keyset.PrimaryKeyId ||
		keyset.Key[0].KeyData.TypeUrl != mac.HmacTypeURL ||
		keyset.Key[0].Status != tinkpb.KeyStatusType_ENABLED ||
		keyset.Key[0].OutputPrefixType != tinkpb.OutputPrefixType_TINK {
		t.Errorf("incorrect key information: %s", keyset.Key[0])
	}
}

func TestEncryptedKeyset(t *testing.T) {
	setupKeysetManagerTest()
	macTemplate := mac.HmacSha256Tag128KeyTemplate()
	aesTemplate := aead.Aes128GcmKeyTemplate()
	keyData, err := tink.NewKeyData(aesTemplate)
	if err != nil {
		t.Errorf("cannot create new key data: %s", err)
	}
	p, err := tink.GetPrimitiveFromKeyData(keyData)
	if p == nil || err != nil {
		t.Errorf("cannot get primitive from key data: %s", err)
	}
	masterKey := p.(tink.Aead)
	manager := tink.NewKeysetManager(macTemplate, masterKey, nil)
	err = manager.Rotate()
	if err != nil {
		t.Errorf("cannot rotate when key template is available: %s", err)
	}
	handle, err := manager.GetKeysetHandle()
	if handle == nil || err != nil {
		t.Errorf("cannot get keyset handle: %s", err)
	}
	info, err := handle.KeysetInfo()
	if info == nil || err != nil {
		t.Errorf("cannot get keyset info: %s", err)
	}
	if len(info.KeyInfo) != 1 {
		t.Errorf("incorrect number of keys: %v", len(info.KeyInfo))
	}
	if info.PrimaryKeyId != info.KeyInfo[0].KeyId {
		t.Errorf("incorrect primary key id: %d >< %d", info.PrimaryKeyId, info.KeyInfo[0].KeyId)
	}
	if info.KeyInfo[0].TypeUrl != mac.HmacTypeURL ||
		info.KeyInfo[0].Status != tinkpb.KeyStatusType_ENABLED ||
		info.KeyInfo[0].OutputPrefixType != tinkpb.OutputPrefixType_TINK {
		t.Errorf("incorrect key info: %s", info.KeyInfo[0])
	}
}

func TestExistingKeyset(t *testing.T) {
	// Create a keyset that contains a single HmacKey.
	macTemplate := mac.HmacSha256Tag128KeyTemplate()
	manager1 := tink.NewKeysetManager(macTemplate, nil, nil)
	err := manager1.Rotate()
	if err != nil {
		t.Errorf("cannot rotate when key template is available: %s", err)
	}
	handle1, err := manager1.GetKeysetHandle()
	if err != nil {
		t.Errorf("cannot get keyset handle: %s", err)
	}
	keyset1 := handle1.Keyset()

	manager2 := tink.NewKeysetManager(nil, nil, keyset1)
	manager2.RotateWithTemplate(macTemplate)
	handle2, err := manager2.GetKeysetHandle()
	if err != nil {
		t.Errorf("cannot get keyset handle: %s", err)
	}
	keyset2 := handle2.Keyset()
	if len(keyset2.Key) != 2 {
		t.Errorf("expect the number of keys to be 2, got %d", len(keyset2.Key))
	}
	if keyset1.Key[0].String() != keyset2.Key[0].String() {
		t.Errorf("expect the first key in two keysets to be the same")
	}
	if keyset2.Key[1].KeyId != keyset2.PrimaryKeyId {
		t.Errorf("expect the second key to be primary")
	}
}

/**
 * Tests that when encryption with KMS failed, an exception is thrown.
 */
func TestFaultyKms(t *testing.T) {
	var masterKey tink.Aead = new(testutil.DummyAead)
	template := mac.HmacSha256Tag128KeyTemplate()
	manager := tink.NewKeysetManager(template, masterKey, nil)
	err := manager.Rotate()
	if err != nil {
		t.Errorf("cannot rotate when key template is available: %s", err)
	}
	_, err = manager.GetKeysetHandle()
	if err == nil || !strings.Contains(err.Error(), "dummy") {
		t.Errorf("expect an error with dummy aead: %s", err)
	}
}
