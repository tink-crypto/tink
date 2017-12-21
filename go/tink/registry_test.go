// Copyright 2017 Google Inc.
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

package tink_test

import (
	"fmt"
	"github.com/golang/protobuf/proto"
	"github.com/google/tink/go/aead/aead"
	"github.com/google/tink/go/mac/mac"
	"github.com/google/tink/go/subtle/aes"
	"github.com/google/tink/go/subtle/hmac"
	"github.com/google/tink/go/tink/tink"
	"github.com/google/tink/go/util/testutil"
	"github.com/google/tink/go/util/util"
	gcmpb "github.com/google/tink/proto/aes_gcm_go_proto"
	commonpb "github.com/google/tink/proto/common_go_proto"
	hmacpb "github.com/google/tink/proto/hmac_go_proto"
	tinkpb "github.com/google/tink/proto/tink_go_proto"
	"sync"
	"testing"
)

func TestKeyManagerMapBasic(t *testing.T) {
	kmMap := tink.NewKeyManagerMap()
	// try to put a HmacKeyManager
	hmacManager := mac.NewHmacKeyManager()
	typeUrl := mac.HMAC_TYPE_URL
	kmMap.Put(typeUrl, hmacManager)
	tmp, existed := kmMap.Get(typeUrl)
	if !existed {
		t.Errorf("a HmacKeyManager should be found")
	}
	var _ = tmp.(*mac.HmacKeyManager)
	// Get type url that doesn't exist
	if _, existed := kmMap.Get("some url"); existed == true {
		t.Errorf("unknown typeUrl shouldn't exist in the map")
	}
}

func TestKeyManagerMapConcurrency(t *testing.T) {
	kmMap := tink.NewKeyManagerMap()
	n := 100
	urlPrefix := "typeUrl#"
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
	km, err = tink.Registry().GetKeyManager(mac.HMAC_TYPE_URL)
	if err != nil {
		t.Errorf("unexpected error: %s", err)
	}
	var _ *mac.HmacKeyManager = km.(*mac.HmacKeyManager)
	// get AesGcmKeyManager
	km, err = tink.Registry().GetKeyManager(aead.AES_GCM_TYPE_URL)
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
	// dummyKeyManager's typeUrl is equal to that of AesGcm
	var dummyKeyManager tink.KeyManager = new(testutil.DummyAeadKeyManager)
	// this should not overwrite the existing manager.
	ok, err := tink.Registry().RegisterKeyManager(dummyKeyManager)
	if ok == true || err != nil {
		t.Errorf("AES_GCM_TYPE_URL shouldn't be registered again")
	}
	km, err := tink.Registry().GetKeyManager(aead.AES_GCM_TYPE_URL)
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
	if keyData.TypeUrl != mac.HMAC_TYPE_URL {
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
		t.Errorf("expect an error when key template contains unregistered typeUrl")
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
	format := util.NewAesGcmKeyFormat(16)
	key, err := tink.Registry().NewKeyFromKeyFormat(aead.AES_GCM_TYPE_URL, format)
	if err != nil {
		t.Errorf("unexpected error: %s", err)
	}
	var aesGcmKey *gcmpb.AesGcmKey = key.(*gcmpb.AesGcmKey)
	if uint32(len(aesGcmKey.KeyValue)) != format.KeySize {
		t.Errorf("key doesn't match format")
	}
	// unregistered url
	if _, err := tink.Registry().NewKeyFromKeyFormat("some url", format); err == nil {
		t.Errorf("expect an error when typeUrl has not been registered")
	}
	// unmatched url
	if _, err := tink.Registry().NewKeyFromKeyFormat(mac.HMAC_TYPE_URL, format); err == nil {
		t.Errorf("expect an error when typeUrl doesn't match format")
	}
	// nil format
	if _, err := tink.Registry().NewKeyFromKeyFormat(mac.HMAC_TYPE_URL, nil); err == nil {
		t.Errorf("expect an error when format is nil")
	}
}

func TestGetPrimitiveFromKey(t *testing.T) {
	setupRegistryTests()
	// hmac key
	key := testutil.NewHmacKey(commonpb.HashType_SHA256, 16)
	p, err := tink.Registry().GetPrimitiveFromKey(mac.HMAC_TYPE_URL, key)
	if err != nil {
		t.Errorf("unexpected error: %s", err)
	}
	var _ *hmac.Hmac = p.(*hmac.Hmac)
	// unregistered url
	if _, err := tink.Registry().GetPrimitiveFromKey("some url", key); err == nil {
		t.Errorf("expect an error when typeUrl has not been registered")
	}
	// unmatched url
	if _, err := tink.Registry().GetPrimitiveFromKey(aead.AES_GCM_TYPE_URL, key); err == nil {
		t.Errorf("expect an error when typeUrl doesn't match key")
	}
	// nil key
	if _, err := tink.Registry().GetPrimitiveFromKey(aead.AES_GCM_TYPE_URL, nil); err == nil {
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
	var _ *hmac.Hmac = p.(*hmac.Hmac)
	// unregistered url
	keyData.TypeUrl = "some url"
	if _, err := tink.Registry().GetPrimitiveFromKeyData(keyData); err == nil {
		t.Errorf("expect an error when typeUrl has not been registered")
	}
	// unmatched url
	keyData.TypeUrl = aead.AES_GCM_TYPE_URL
	if _, err := tink.Registry().GetPrimitiveFromKeyData(keyData); err == nil {
		t.Errorf("expect an error when typeUrl doesn't match key")
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
	p, err := tink.Registry().GetPrimitiveFromSerializedKey(mac.HMAC_TYPE_URL, serializedKey)
	if err != nil {
		t.Errorf("unexpected error: %s", err)
	}
	var _ *hmac.Hmac = p.(*hmac.Hmac)
	// unregistered url
	if _, err := tink.Registry().GetPrimitiveFromSerializedKey("some url", serializedKey); err == nil {
		t.Errorf("expect an error when typeUrl has not been registered")
	}
	// unmatched url
	if _, err := tink.Registry().GetPrimitiveFromSerializedKey(aead.AES_GCM_TYPE_URL, serializedKey); err == nil {
		t.Errorf("expect an error when typeUrl doesn't match key")
	}
	// void key
	if _, err := tink.Registry().GetPrimitiveFromSerializedKey(aead.AES_GCM_TYPE_URL, nil); err == nil {
		t.Errorf("expect an error when key is nil")
	}
	if _, err := tink.Registry().GetPrimitiveFromSerializedKey(aead.AES_GCM_TYPE_URL, []byte{}); err == nil {
		t.Errorf("expect an error when key is nil")
	}
	if _, err := tink.Registry().GetPrimitiveFromSerializedKey(aead.AES_GCM_TYPE_URL, []byte{0}); err == nil {
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
	keyset := util.NewKeyset(2, []*tinkpb.Keyset_Key{
		util.NewKey(keyData1, tinkpb.KeyStatusType_ENABLED, 1, tinkpb.OutputPrefixType_TINK),
		util.NewKey(keyData2, tinkpb.KeyStatusType_ENABLED, 2, tinkpb.OutputPrefixType_TINK),
	})
	handle, _ := tink.CleartextKeysetHandle().ParseKeyset(keyset)
	ps, err := tink.Registry().GetPrimitives(handle)
	if err != nil {
		t.Errorf("unexpected error: %s", err)
	}
	var aesGcm *aes.AesGcm = ps.Primary().Primitive().(*aes.AesGcm)
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
	keyset = util.NewKeyset(1, []*tinkpb.Keyset_Key{})
	handle, _ = tink.CleartextKeysetHandle().ParseKeyset(keyset)
	if _, err := tink.Registry().GetPrimitives(handle); err == nil {
		t.Errorf("expect an error when keyset is empty")
	}
	keyset = util.NewKeyset(1, nil)
	handle, _ = tink.CleartextKeysetHandle().ParseKeyset(keyset)
	if _, err := tink.Registry().GetPrimitives(handle); err == nil {
		t.Errorf("expect an error when keyset is empty")
	}
	// no primary key
	keyset = util.NewKeyset(3, []*tinkpb.Keyset_Key{
		util.NewKey(keyData1, tinkpb.KeyStatusType_ENABLED, 1, tinkpb.OutputPrefixType_TINK),
		util.NewKey(keyData2, tinkpb.KeyStatusType_ENABLED, 2, tinkpb.OutputPrefixType_TINK),
	})
	handle, _ = tink.CleartextKeysetHandle().ParseKeyset(keyset)
	if _, err := tink.Registry().GetPrimitives(handle); err == nil {
		t.Errorf("expect an error when there is no primary key")
	}
	// there is primary key but it is disabled
	keyset = util.NewKeyset(1, []*tinkpb.Keyset_Key{
		util.NewKey(keyData1, tinkpb.KeyStatusType_DISABLED, 1, tinkpb.OutputPrefixType_TINK),
		util.NewKey(keyData2, tinkpb.KeyStatusType_ENABLED, 2, tinkpb.OutputPrefixType_TINK),
	})
	handle, _ = tink.CleartextKeysetHandle().ParseKeyset(keyset)
	if _, err := tink.Registry().GetPrimitives(handle); err == nil {
		t.Errorf("expect an error when primary key is disabled")
	}
	// multiple primary keys
	keyset = util.NewKeyset(1, []*tinkpb.Keyset_Key{
		util.NewKey(keyData1, tinkpb.KeyStatusType_ENABLED, 1, tinkpb.OutputPrefixType_TINK),
		util.NewKey(keyData2, tinkpb.KeyStatusType_ENABLED, 1, tinkpb.OutputPrefixType_TINK),
	})
	handle, _ = tink.CleartextKeysetHandle().ParseKeyset(keyset)
	if _, err := tink.Registry().GetPrimitives(handle); err == nil {
		t.Errorf("expect an error when there are multiple primary keys")
	}
}
