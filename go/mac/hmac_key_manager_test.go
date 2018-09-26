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

package mac_test

import (
	"bytes"
	"fmt"
	"reflect"
	"testing"

	"github.com/golang/protobuf/proto"
	"github.com/google/tink/go/mac"
	subtleMac "github.com/google/tink/go/subtle/mac"
	"github.com/google/tink/go/subtle/random"
	"github.com/google/tink/go/subtle"
	"github.com/google/tink/go/testutil"
	"github.com/google/tink/go/tink"
	commonpb "github.com/google/tink/proto/common_go_proto"
	hmacpb "github.com/google/tink/proto/hmac_go_proto"
	tinkpb "github.com/google/tink/proto/tink_go_proto"
)

func TestGetPrimitiveBasic(t *testing.T) {
	km := mac.NewHmacKeyManager()
	testKeys := genValidHmacKeys()
	for i := 0; i < len(testKeys); i++ {
		serializedKey, _ := proto.Marshal(testKeys[i])
		p, err := km.Primitive(serializedKey)
		if err != nil {
			t.Errorf("unexpected error in test case %d: %s", i, err)
		}
		if err := validateHmacPrimitive(p, testKeys[i]); err != nil {
			t.Errorf("%s", err)
		}
	}
}

func TestGetPrimitiveWithInvalidInput(t *testing.T) {
	km := mac.NewHmacKeyManager()
	// invalid key
	testKeys := genInvalidHmacKeys()
	for i := 0; i < len(testKeys); i++ {
		serializedKey, _ := proto.Marshal(testKeys[i])
		if _, err := km.Primitive(serializedKey); err == nil {
			t.Errorf("expect an error in test case %d", i)
		}
	}
	if _, err := km.Primitive(nil); err == nil {
		t.Errorf("expect an error when input is nil")
	}
	// empty input
	if _, err := km.Primitive([]byte{}); err == nil {
		t.Errorf("expect an error when input is empty")
	}
}

func TestNewKeyMultipleTimes(t *testing.T) {
	km := mac.NewHmacKeyManager()
	serializedFormat, _ := proto.Marshal(testutil.NewHmacKeyFormat(commonpb.HashType_SHA256, 32))
	keys := make(map[string]bool)
	nTest := 26
	for i := 0; i < nTest; i++ {
		key, _ := km.NewKey(serializedFormat)
		serializedKey, _ := proto.Marshal(key)
		keys[string(serializedKey)] = true

		keyData, _ := km.NewKeyData(serializedFormat)
		serializedKey = keyData.Value
		keys[string(serializedKey)] = true
	}
	if len(keys) != nTest*2 {
		t.Errorf("key is repeated")
	}
}

func TestNewKeyBasic(t *testing.T) {
	km := mac.NewHmacKeyManager()
	testFormats := genValidHmacKeyFormats()
	for i := 0; i < len(testFormats); i++ {
		serializedFormat, _ := proto.Marshal(testFormats[i])
		key, err := km.NewKey(serializedFormat)
		if err != nil {
			t.Errorf("unexpected error in test case %d: %s", i, err)
		}
		if err := validateHmacKey(testFormats[i], key.(*hmacpb.HmacKey)); err != nil {
			t.Errorf("%s", err)
		}
	}
}

func TestNewKeyWithInvalidInput(t *testing.T) {
	km := mac.NewHmacKeyManager()
	// invalid key formats
	testFormats := genInvalidHmacKeyFormats()
	for i := 0; i < len(testFormats); i++ {
		serializedFormat, err := proto.Marshal(testFormats[i])
		if err != nil {
			fmt.Println("Error!")
		}
		if _, err := km.NewKey(serializedFormat); err == nil {
			t.Errorf("expect an error in test case %d: %s", i, err)
		}
	}
	if _, err := km.NewKey(nil); err == nil {
		t.Errorf("expect an error when input is nil")
	}
	// empty input
	if _, err := km.NewKey([]byte{}); err == nil {
		t.Errorf("expect an error when input is empty")
	}
}

func TestNewKeyDataBasic(t *testing.T) {
	km := mac.NewHmacKeyManager()
	testFormats := genValidHmacKeyFormats()
	for i := 0; i < len(testFormats); i++ {
		serializedFormat, _ := proto.Marshal(testFormats[i])
		keyData, err := km.NewKeyData(serializedFormat)
		if err != nil {
			t.Errorf("unexpected error in test case %d: %s", i, err)
		}
		if keyData.TypeUrl != mac.HmacTypeURL {
			t.Errorf("incorrect type url in test case %d", i)
		}
		if keyData.KeyMaterialType != tinkpb.KeyData_SYMMETRIC {
			t.Errorf("incorrect key material type in test case %d", i)
		}
		key := new(hmacpb.HmacKey)
		if err := proto.Unmarshal(keyData.Value, key); err != nil {
			t.Errorf("invalid key value")
		}
		if err := validateHmacKey(testFormats[i], key); err != nil {
			t.Errorf("invalid key")
		}
	}
}

func TestNewKeyDataWithInvalidInput(t *testing.T) {
	km := mac.NewHmacKeyManager()
	// invalid key formats
	testFormats := genInvalidHmacKeyFormats()
	for i := 0; i < len(testFormats); i++ {
		serializedFormat, _ := proto.Marshal(testFormats[i])
		if _, err := km.NewKeyData(serializedFormat); err == nil {
			t.Errorf("expect an error in test case %d", i)
		}
	}
	// nil input
	if _, err := km.NewKeyData(nil); err == nil {
		t.Errorf("expect an error when input is nil")
	}
}

func TestDoesSupport(t *testing.T) {
	km := mac.NewHmacKeyManager()
	if !km.DoesSupport(mac.HmacTypeURL) {
		t.Errorf("HmacKeyManager must support %s", mac.HmacTypeURL)
	}
	if km.DoesSupport("some bad type") {
		t.Errorf("HmacKeyManager must support only %s", mac.HmacTypeURL)
	}
}

func TestTypeURL(t *testing.T) {
	km := mac.NewHmacKeyManager()
	if km.TypeURL() != mac.HmacTypeURL {
		t.Errorf("incorrect GetKeyType()")
	}
}

func TestKeyManagerInterface(t *testing.T) {
	// This line results in a compilation error if HmacKeyManger doesn't implement the KeyManager
	// interface.
	var _ tink.KeyManager = (*mac.HmacKeyManager)(nil)
}

func genInvalidHmacKeys() []proto.Message {
	badVersionKey := testutil.NewHmacKey(commonpb.HashType_SHA256, 32)
	badVersionKey.Version++
	shortKey := testutil.NewHmacKey(commonpb.HashType_SHA256, 32)
	shortKey.KeyValue = []byte{1, 1}
	return []proto.Message{
		// not a HmacKey
		mac.NewHmacParams(commonpb.HashType_SHA256, 32),
		// bad version
		badVersionKey,
		// tag size too big
		testutil.NewHmacKey(commonpb.HashType_SHA1, 21),
		testutil.NewHmacKey(commonpb.HashType_SHA256, 33),
		testutil.NewHmacKey(commonpb.HashType_SHA512, 65),
		// tag size too small
		testutil.NewHmacKey(commonpb.HashType_SHA256, 1),
		// key too short
		shortKey,
		// unknown hash type
		testutil.NewHmacKey(commonpb.HashType_UNKNOWN_HASH, 32),
	}
}

func genInvalidHmacKeyFormats() []proto.Message {
	shortKeyFormat := testutil.NewHmacKeyFormat(commonpb.HashType_SHA256, 32)
	shortKeyFormat.KeySize = 1
	return []proto.Message{
		// not a HmacKeyFormat
		mac.NewHmacParams(commonpb.HashType_SHA256, 32),
		// tag size too big
		testutil.NewHmacKeyFormat(commonpb.HashType_SHA1, 21),
		testutil.NewHmacKeyFormat(commonpb.HashType_SHA256, 33),
		testutil.NewHmacKeyFormat(commonpb.HashType_SHA512, 65),
		// tag size too small
		testutil.NewHmacKeyFormat(commonpb.HashType_SHA256, 1),
		// key too short
		shortKeyFormat,
		// unknown hash type
		testutil.NewHmacKeyFormat(commonpb.HashType_UNKNOWN_HASH, 32),
	}
}

func genValidHmacKeyFormats() []*hmacpb.HmacKeyFormat {
	return []*hmacpb.HmacKeyFormat{
		testutil.NewHmacKeyFormat(commonpb.HashType_SHA1, 20),
		testutil.NewHmacKeyFormat(commonpb.HashType_SHA256, 32),
		testutil.NewHmacKeyFormat(commonpb.HashType_SHA512, 64),
	}
}

func genValidHmacKeys() []*hmacpb.HmacKey {
	return []*hmacpb.HmacKey{
		testutil.NewHmacKey(commonpb.HashType_SHA1, 20),
		testutil.NewHmacKey(commonpb.HashType_SHA256, 32),
		testutil.NewHmacKey(commonpb.HashType_SHA512, 64),
	}
}

// Checks whether the given HmacKey matches the given key HmacKeyFormat
func validateHmacKey(format *hmacpb.HmacKeyFormat, key *hmacpb.HmacKey) error {
	if format.KeySize != uint32(len(key.KeyValue)) ||
		key.Params.TagSize != format.Params.TagSize ||
		key.Params.Hash != format.Params.Hash {
		return fmt.Errorf("key format and generated key do not match")
	}
	p, err := subtleMac.NewHmac(tink.GetHashName(key.Params.Hash), key.KeyValue, key.Params.TagSize)
	if err != nil {
		return fmt.Errorf("cannot create primitive from key: %s", err)
	}
	return validateHmacPrimitive(p, key)
}

// validateHmacPrimitive checks whether the given primitive matches the given HmacKey
func validateHmacPrimitive(p interface{}, key *hmacpb.HmacKey) error {
	hmacPrimitive := p.(*subtleMac.Hmac)
	if !bytes.Equal(hmacPrimitive.Key, key.KeyValue) ||
		hmacPrimitive.TagSize != key.Params.TagSize ||
		reflect.ValueOf(hmacPrimitive.HashFunc).Pointer() !=
			reflect.ValueOf(subtle.GetHashFunc(tink.GetHashName(key.Params.Hash))).Pointer() {
		return fmt.Errorf("primitive and key do not matched")
	}
	data := random.GetRandomBytes(20)
	mac, err := hmacPrimitive.ComputeMac(data)
	if err != nil {
		return fmt.Errorf("mac computation failed: %s", err)
	}
	if valid, err := hmacPrimitive.VerifyMac(mac, data); !valid || err != nil {
		return fmt.Errorf("mac verification failed: %s", err)
	}
	return nil
}
