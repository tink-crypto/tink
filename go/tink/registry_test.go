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
	"sync"
	"testing"

	"github.com/golang/protobuf/proto"
	"github.com/google/tink/go/aead"
	"github.com/google/tink/go/mac"
	subtleAead "github.com/google/tink/go/subtle/aead"
	subtleMac "github.com/google/tink/go/subtle/mac"
	"github.com/google/tink/go/testutil"
	"github.com/google/tink/go/tink"
	gcmpb "github.com/google/tink/proto/aes_gcm_go_proto"
	commonpb "github.com/google/tink/proto/common_go_proto"
	hmacpb "github.com/google/tink/proto/hmac_go_proto"
	tinkpb "github.com/google/tink/proto/tink_go_proto"
)

func TestKeyManagerMapBasic(t *testing.T) {
	kmMap := tink.NewKeyManagerMap()
	// try to put a HmacKeyManager
	hmacManager := mac.NewHmacKeyManager()
	typeURL := mac.HmacTypeURL
	kmMap.Put(typeURL, hmacManager)
	tmp, existed := kmMap.Get(typeURL)
	if !existed {
		t.Errorf("a HmacKeyManager should be found")
	}
	var _ = tmp.(*mac.HmacKeyManager)
	// Get type url that doesn't exist
	if _, existed := kmMap.Get("some url"); existed {
		t.Errorf("unknown typeURL shouldn't exist in the map")
	}
}

func TestKeyManagerMapConcurrency(t *testing.T) {
	kmMap := tink.NewKeyManagerMap()
	n := 100
	urlPrefix := "typeURL#"
	// put
	var wg sync.WaitGroup
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func(i int) {
			defer wg.Done()
			hmacManager := mac.NewHmacKeyManager()
			kmMap.Put(fmt.Sprintf("%s%d", urlPrefix, i), hmacManager)
		}(i)
	}
	wg.Wait()
	// get
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func(i int) {
			defer wg.Done()
			km, existed := kmMap.Get(fmt.Sprintf("%s%d", urlPrefix, i))
			var _ = km.(*mac.HmacKeyManager)
			if !existed {
				t.Errorf("key manager %d is missing", i)
			}
		}(i)
	}
	wg.Wait()
}

func setupRegistryTests() {
	_, err := mac.Config().RegisterStandardKeyTypes()
	if err != nil {
		panic("cannot register Mac key types")
	}
	_, err = aead.Config().RegisterStandardKeyTypes()
	if err != nil {
		panic("cannot register Aead key types")
	}
}

func TestKeyManagerRegistration(t *testing.T) {
	var km tink.KeyManager
	var err error
	// register mac and aead types.
	setupRegistryTests()
	// get HmacKeyManager
	km, err = tink.Registry().GetKeyManager(mac.HmacTypeURL)
	if err != nil {
		t.Errorf("unexpected error: %s", err)
	}
	var _ *mac.HmacKeyManager = km.(*mac.HmacKeyManager)
	// get AesGcmKeyManager
	km, err = tink.Registry().GetKeyManager(aead.AesGcmTypeURL)
	if err != nil {
		t.Errorf("unexpected error: %s", err)
	}
	var _ *aead.AesGcmKeyManager = km.(*aead.AesGcmKeyManager)
	// some random typeurl
	if _, err = tink.Registry().GetKeyManager("some url"); err == nil {
		t.Errorf("expect an error when a type url doesn't exist in the registry")
	}
}

func TestKeyManagerRegistrationWithCollision(t *testing.T) {
	// register mac and aead types.
	setupRegistryTests()
	// dummyKeyManager's typeURL is equal to that of AesGcm
	var dummyKeyManager tink.KeyManager = new(testutil.DummyAeadKeyManager)
	// this should not overwrite the existing manager.
	ok, err := tink.Registry().RegisterKeyManager(dummyKeyManager)
	if ok || err != nil {
		t.Errorf("AES_GCM_TYPE_URL shouldn't be registered again")
	}
	km, err := tink.Registry().GetKeyManager(aead.AesGcmTypeURL)
	if err != nil {
		t.Errorf("unexpected error: %s", err)
	}
	var _ *aead.AesGcmKeyManager = km.(*aead.AesGcmKeyManager)
}

func TestNewKeyData(t *testing.T) {
	setupRegistryTests()
	// new Keydata from a Hmac KeyTemplate
	keyData, err := tink.Registry().NewKeyData(mac.HmacSha256Tag128KeyTemplate())
	if err != nil {
		t.Errorf("unexpected error: %s", err)
	}
	if keyData.TypeUrl != mac.HmacTypeURL {
		t.Errorf("invalid key data")
	}
	key := new(hmacpb.HmacKey)
	if err := proto.Unmarshal(keyData.Value, key); err != nil {
		t.Errorf("unexpected error when unmarshal HmacKey: %s", err)
	}
	// nil
	if _, err := tink.Registry().NewKeyData(nil); err == nil {
		t.Errorf("expect an error when key template is nil")
	}
	// unregistered type url
	template := &tinkpb.KeyTemplate{TypeUrl: "some url", Value: []byte{0}}
	if _, err := tink.Registry().NewKeyData(template); err == nil {
		t.Errorf("expect an error when key template contains unregistered typeURL")
	}
}

func TestNewKeyFromKeyTemplate(t *testing.T) {
	setupRegistryTests()
	// aead template
	aesGcmTemplate := aead.Aes128GcmKeyTemplate()
	key, err := tink.Registry().NewKeyFromKeyTemplate(aesGcmTemplate)
	if err != nil {
		t.Errorf("unexpected error: %s", err)
	}
	var aesGcmKey *gcmpb.AesGcmKey = key.(*gcmpb.AesGcmKey)
	aesGcmFormat := new(gcmpb.AesGcmKeyFormat)
	if err := proto.Unmarshal(aesGcmTemplate.Value, aesGcmFormat); err != nil {
		t.Errorf("unexpected error: %s", err)
	}
	if aesGcmFormat.KeySize != uint32(len(aesGcmKey.KeyValue)) {
		t.Errorf("key doesn't match template")
	}
	//nil
	if _, err := tink.Registry().NewKeyFromKeyTemplate(nil); err == nil {
		t.Errorf("expect an error when key template is nil")
	}
	// unregistered type url
	template := &tinkpb.KeyTemplate{TypeUrl: "some url", Value: []byte{0}}
	if _, err := tink.Registry().NewKeyFromKeyTemplate(template); err == nil {
		t.Errorf("expect an error when key template is not registered")
	}
}

func TestNewKeyFromKeyFormat(t *testing.T) {
	setupRegistryTests()
	// use aes-gcm key format
	format := aead.NewAesGcmKeyFormat(16)
	key, err := tink.Registry().NewKeyFromKeyFormat(aead.AesGcmTypeURL, format)
	if err != nil {
		t.Errorf("unexpected error: %s", err)
	}
	var aesGcmKey *gcmpb.AesGcmKey = key.(*gcmpb.AesGcmKey)
	if uint32(len(aesGcmKey.KeyValue)) != format.KeySize {
		t.Errorf("key doesn't match format")
	}
	// unregistered url
	if _, err := tink.Registry().NewKeyFromKeyFormat("some url", format); err == nil {
		t.Errorf("expect an error when typeURL has not been registered")
	}
	// unmatched url
	if _, err := tink.Registry().NewKeyFromKeyFormat(mac.HmacTypeURL, format); err == nil {
		t.Errorf("expect an error when typeURL doesn't match format")
	}
	// nil format
	if _, err := tink.Registry().NewKeyFromKeyFormat(mac.HmacTypeURL, nil); err == nil {
		t.Errorf("expect an error when format is nil")
	}
}

func TestGetPrimitiveFromKey(t *testing.T) {
	setupRegistryTests()
	// hmac key
	key := testutil.NewHmacKey(commonpb.HashType_SHA256, 16)
	p, err := tink.Registry().GetPrimitiveFromKey(mac.HmacTypeURL, key)
	if err != nil {
		t.Errorf("unexpected error: %s", err)
	}
	var _ *subtleMac.Hmac = p.(*subtleMac.Hmac)
	// unregistered url
	if _, err := tink.Registry().GetPrimitiveFromKey("some url", key); err == nil {
		t.Errorf("expect an error when typeURL has not been registered")
	}
	// unmatched url
	if _, err := tink.Registry().GetPrimitiveFromKey(aead.AesGcmTypeURL, key); err == nil {
		t.Errorf("expect an error when typeURL doesn't match key")
	}
	// nil key
	if _, err := tink.Registry().GetPrimitiveFromKey(aead.AesGcmTypeURL, nil); err == nil {
		t.Errorf("expect an error when key is nil")
	}
}

func TestGetPrimitiveFromKeyData(t *testing.T) {
	setupRegistryTests()
	// hmac keydata
	keyData := testutil.NewHmacKeyData(commonpb.HashType_SHA256, 16)
	p, err := tink.Registry().GetPrimitiveFromKeyData(keyData)
	if err != nil {
		t.Errorf("unexpected error: %s", err)
	}
	var _ *subtleMac.Hmac = p.(*subtleMac.Hmac)
	// unregistered url
	keyData.TypeUrl = "some url"
	if _, err := tink.Registry().GetPrimitiveFromKeyData(keyData); err == nil {
		t.Errorf("expect an error when typeURL has not been registered")
	}
	// unmatched url
	keyData.TypeUrl = aead.AesGcmTypeURL
	if _, err := tink.Registry().GetPrimitiveFromKeyData(keyData); err == nil {
		t.Errorf("expect an error when typeURL doesn't match key")
	}
	// nil
	if _, err := tink.Registry().GetPrimitiveFromKeyData(nil); err == nil {
		t.Errorf("expect an error when key data is nil")
	}
}

func TestGetPrimitiveFromSerializedKey(t *testing.T) {
	setupRegistryTests()
	// hmac key
	key := testutil.NewHmacKey(commonpb.HashType_SHA256, 16)
	serializedKey, _ := proto.Marshal(key)
	p, err := tink.Registry().GetPrimitiveFromSerializedKey(mac.HmacTypeURL, serializedKey)
	if err != nil {
		t.Errorf("unexpected error: %s", err)
	}
	var _ *subtleMac.Hmac = p.(*subtleMac.Hmac)
	// unregistered url
	if _, err := tink.Registry().GetPrimitiveFromSerializedKey("some url", serializedKey); err == nil {
		t.Errorf("expect an error when typeURL has not been registered")
	}
	// unmatched url
	if _, err := tink.Registry().GetPrimitiveFromSerializedKey(aead.AesGcmTypeURL, serializedKey); err == nil {
		t.Errorf("expect an error when typeURL doesn't match key")
	}
	// void key
	if _, err := tink.Registry().GetPrimitiveFromSerializedKey(aead.AesGcmTypeURL, nil); err == nil {
		t.Errorf("expect an error when key is nil")
	}
	if _, err := tink.Registry().GetPrimitiveFromSerializedKey(aead.AesGcmTypeURL, []byte{}); err == nil {
		t.Errorf("expect an error when key is nil")
	}
	if _, err := tink.Registry().GetPrimitiveFromSerializedKey(aead.AesGcmTypeURL, []byte{0}); err == nil {
		t.Errorf("expect an error when key is nil")
	}
}

func TestGetPrimitives(t *testing.T) {
	setupRegistryTests()
	// valid input
	template1 := aead.Aes128GcmKeyTemplate()
	template2 := aead.Aes256GcmKeyTemplate()
	keyData1, _ := tink.Registry().NewKeyData(template1)
	keyData2, _ := tink.Registry().NewKeyData(template2)
	keyset := tink.NewKeyset(2, []*tinkpb.Keyset_Key{
		tink.NewKey(keyData1, tinkpb.KeyStatusType_ENABLED, 1, tinkpb.OutputPrefixType_TINK),
		tink.NewKey(keyData2, tinkpb.KeyStatusType_ENABLED, 2, tinkpb.OutputPrefixType_TINK),
	})
	handle, _ := tink.CleartextKeysetHandle().ParseKeyset(keyset)
	ps, err := tink.Registry().GetPrimitives(handle)
	if err != nil {
		t.Errorf("unexpected error: %s", err)
	}
	var aesGcm *subtleAead.AesGcm = ps.Primary().Primitive().(*subtleAead.AesGcm)
	if len(aesGcm.Key) != 32 {
		t.Errorf("primitive doesn't match input keyset handle")
	}
	// custom manager
	customManager := new(testutil.DummyAeadKeyManager)
	ps, err = tink.Registry().GetPrimitivesWithCustomManager(handle, customManager)
	if err != nil {
		t.Errorf("unexpected error: %s", err)
	}
	var _ *testutil.DummyAead = ps.Primary().Primitive().(*testutil.DummyAead)
	// keysethandle is nil
	if _, err := tink.Registry().GetPrimitives(nil); err == nil {
		t.Errorf("expect an error when keysethandle is nil")
	}
	// keyset is empty
	keyset = tink.NewKeyset(1, []*tinkpb.Keyset_Key{})
	handle, _ = tink.CleartextKeysetHandle().ParseKeyset(keyset)
	if _, err := tink.Registry().GetPrimitives(handle); err == nil {
		t.Errorf("expect an error when keyset is empty")
	}
	keyset = tink.NewKeyset(1, nil)
	handle, _ = tink.CleartextKeysetHandle().ParseKeyset(keyset)
	if _, err := tink.Registry().GetPrimitives(handle); err == nil {
		t.Errorf("expect an error when keyset is empty")
	}
	// no primary key
	keyset = tink.NewKeyset(3, []*tinkpb.Keyset_Key{
		tink.NewKey(keyData1, tinkpb.KeyStatusType_ENABLED, 1, tinkpb.OutputPrefixType_TINK),
		tink.NewKey(keyData2, tinkpb.KeyStatusType_ENABLED, 2, tinkpb.OutputPrefixType_TINK),
	})
	handle, _ = tink.CleartextKeysetHandle().ParseKeyset(keyset)
	if _, err := tink.Registry().GetPrimitives(handle); err == nil {
		t.Errorf("expect an error when there is no primary key")
	}
	// there is primary key but it is disabled
	keyset = tink.NewKeyset(1, []*tinkpb.Keyset_Key{
		tink.NewKey(keyData1, tinkpb.KeyStatusType_DISABLED, 1, tinkpb.OutputPrefixType_TINK),
		tink.NewKey(keyData2, tinkpb.KeyStatusType_ENABLED, 2, tinkpb.OutputPrefixType_TINK),
	})
	handle, _ = tink.CleartextKeysetHandle().ParseKeyset(keyset)
	if _, err := tink.Registry().GetPrimitives(handle); err == nil {
		t.Errorf("expect an error when primary key is disabled")
	}
	// multiple primary keys
	keyset = tink.NewKeyset(1, []*tinkpb.Keyset_Key{
		tink.NewKey(keyData1, tinkpb.KeyStatusType_ENABLED, 1, tinkpb.OutputPrefixType_TINK),
		tink.NewKey(keyData2, tinkpb.KeyStatusType_ENABLED, 1, tinkpb.OutputPrefixType_TINK),
	})
	handle, _ = tink.CleartextKeysetHandle().ParseKeyset(keyset)
	if _, err := tink.Registry().GetPrimitives(handle); err == nil {
		t.Errorf("expect an error when there are multiple primary keys")
	}
}
