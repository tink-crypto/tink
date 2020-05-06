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

package prf_test

import (
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/golang/protobuf/proto"
	"github.com/google/tink/go/core/registry"
	"github.com/google/tink/go/prf"
	"github.com/google/tink/go/testutil"
	cmacpb "github.com/google/tink/go/proto/aes_cmac_prf_go_proto"
	commonpb "github.com/google/tink/go/proto/common_go_proto"
	hkdfpb "github.com/google/tink/go/proto/hkdf_prf_go_proto"
	hmacpb "github.com/google/tink/go/proto/hmac_prf_go_proto"
	tinkpb "github.com/google/tink/go/proto/tink_go_proto"
)

func TestTemplates(t *testing.T) {
	template := prf.HMACSHA256PRFKeyTemplate()
	if err := checkHMACTemplate(template, 32, commonpb.HashType_SHA256); err != nil {
		t.Errorf("incorrect HMACSHA256PRFKeyTemplate: %s", err)
	}
	template = prf.HMACSHA512PRFKeyTemplate()
	if err := checkHMACTemplate(template, 64, commonpb.HashType_SHA512); err != nil {
		t.Errorf("incorrect HMACSHA512PRFKeyTemplate: %s", err)
	}
	template = prf.HKDFSHA256PRFKeyTemplate()
	if err := checkHKDFTemplate(template, 32, make([]byte, 0), commonpb.HashType_SHA256); err != nil {
		t.Errorf("incorrect HKDFSHA256PRFKeyTemplate: %s", err)
	}
	template = prf.AESCMACPRFKeyTemplate()
	if err := checkCMACTemplate(template, 32); err != nil {
		t.Errorf("incorrect AESCMACSPRFKeyTemplate: %s", err)
	}

}

func checkHMACTemplate(template *tinkpb.KeyTemplate, keySize uint32, hashType commonpb.HashType) error {
	if template.TypeUrl != testutil.HMACPRFTypeURL {
		return fmt.Errorf("TypeUrl is incorrect")
	}
	if template.OutputPrefixType != tinkpb.OutputPrefixType_RAW {
		return fmt.Errorf("Not RAW output prefix")
	}
	format := new(hmacpb.HmacPrfKeyFormat)
	if err := proto.Unmarshal(template.Value, format); err != nil {
		return fmt.Errorf("unable to unmarshal serialized key format")
	}
	if format.KeySize != keySize ||
		format.Params.Hash != hashType {
		return fmt.Errorf("KeyFormat is incorrect")
	}
	keymanager, err := registry.GetKeyManager(testutil.HMACPRFTypeURL)
	if err != nil {
		return fmt.Errorf("Could not obtain HMAC key manager: %v", err)
	}
	_, err = keymanager.NewKey(template.Value)
	if err != nil {
		return fmt.Errorf("HMAC key manager cannot create key: %v", err)
	}
	return nil
}

func checkHKDFTemplate(template *tinkpb.KeyTemplate, keySize uint32, salt []byte, hashType commonpb.HashType) error {
	if template.TypeUrl != testutil.HKDFPRFTypeURL {
		return fmt.Errorf("TypeUrl is incorrect")
	}
	if template.OutputPrefixType != tinkpb.OutputPrefixType_RAW {
		return fmt.Errorf("Not RAW output prefix")
	}
	format := new(hkdfpb.HkdfPrfKeyFormat)
	if err := proto.Unmarshal(template.Value, format); err != nil {
		return fmt.Errorf("unable to unmarshal serialized key format")
	}
	if format.KeySize != keySize ||
		format.Params.Hash != hashType ||
		hex.EncodeToString(salt) != hex.EncodeToString(format.Params.Salt) {
		return fmt.Errorf("KeyFormat is incorrect")
	}
	keymanager, err := registry.GetKeyManager(testutil.HKDFPRFTypeURL)
	if err != nil {
		return fmt.Errorf("Could not obtain HMAC key manager: %v", err)
	}
	_, err = keymanager.NewKey(template.Value)
	if err != nil {
		return fmt.Errorf("HMAC key manager cannot create key: %v", err)
	}
	return nil
}

func checkCMACTemplate(template *tinkpb.KeyTemplate, keySize uint32) error {
	if template.TypeUrl != testutil.AESCMACPRFTypeURL {
		return fmt.Errorf("TypeUrl is incorrect")
	}
	if template.OutputPrefixType != tinkpb.OutputPrefixType_RAW {
		return fmt.Errorf("Not RAW output prefix")
	}
	format := new(cmacpb.AesCmacPrfKeyFormat)
	if err := proto.Unmarshal(template.Value, format); err != nil {
		return fmt.Errorf("unable to unmarshal serialized key format")
	}
	if format.KeySize != keySize {
		return fmt.Errorf("KeyFormat is incorrect")
	}
	keymanager, err := registry.GetKeyManager(testutil.AESCMACPRFTypeURL)
	if err != nil {
		return fmt.Errorf("Could not obtain HMAC key manager: %v", err)
	}
	_, err = keymanager.NewKey(template.Value)
	if err != nil {
		return fmt.Errorf("HMAC key manager cannot create key: %v", err)
	}
	return nil
}
