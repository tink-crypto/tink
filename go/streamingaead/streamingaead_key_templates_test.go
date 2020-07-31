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

package streamingaead_test

import (
	"fmt"
	"testing"

	"github.com/golang/protobuf/proto"
	"github.com/google/tink/go/streamingaead"
	"github.com/google/tink/go/testutil"
	ctrhmacpb "github.com/google/tink/go/proto/aes_ctr_hmac_streaming_go_proto"
	gcmhkdfpb "github.com/google/tink/go/proto/aes_gcm_hkdf_streaming_go_proto"
	commonpb "github.com/google/tink/go/proto/common_go_proto"
	tinkpb "github.com/google/tink/go/proto/tink_go_proto"
)

func TestAESGCMHKDFKeyTemplates(t *testing.T) {
	tcs := []struct {
		name                  string
		tmpl                  *tinkpb.KeyTemplate
		keySize               uint32
		ciphertextSegmentSize uint32
	}{
		{
			name:                  "AES128GCMHKDF4KBKeyTemplate",
			tmpl:                  streamingaead.AES128GCMHKDF4KBKeyTemplate(),
			keySize:               16,
			ciphertextSegmentSize: 4096,
		},
		{
			name:                  "AES128GCMHKDF1MBKeyTemplate",
			tmpl:                  streamingaead.AES128GCMHKDF1MBKeyTemplate(),
			keySize:               16,
			ciphertextSegmentSize: 1048576,
		},
		{
			name:                  "AES256GCMHKDF4KBKeyTemplate",
			tmpl:                  streamingaead.AES256GCMHKDF4KBKeyTemplate(),
			keySize:               32,
			ciphertextSegmentSize: 4096,
		},
		{
			name:                  "AES256GCMHKDF1MBKeyTemplate",
			tmpl:                  streamingaead.AES256GCMHKDF1MBKeyTemplate(),
			keySize:               32,
			ciphertextSegmentSize: 1048576,
		},
	}
	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			err := checkAESGCMHKDFKeyTemplate(
				tc.tmpl,
				tc.keySize,
				commonpb.HashType_SHA256,
				tc.ciphertextSegmentSize,
				tinkpb.OutputPrefixType_RAW,
			)
			if err != nil {
				t.Error(err)
			}
		})
	}
}

func checkAESGCMHKDFKeyTemplate(
	template *tinkpb.KeyTemplate,
	keySize uint32,
	hkdfHashType commonpb.HashType,
	ciphertextSegmentSize uint32,
	outputPrefixType tinkpb.OutputPrefixType,
) error {
	if template.TypeUrl != testutil.AESGCMHKDFTypeURL {
		return fmt.Errorf("incorrect type url")
	}
	if template.OutputPrefixType != outputPrefixType {
		return fmt.Errorf("incorrect output prefix type")
	}
	keyFormat := new(gcmhkdfpb.AesGcmHkdfStreamingKeyFormat)
	err := proto.Unmarshal(template.Value, keyFormat)
	if err != nil {
		return fmt.Errorf("cannot deserialize key format: %s", err)
	}
	if keyFormat.KeySize != keySize {
		return fmt.Errorf("incorrect main key size, expect %d, got %d", keySize, keyFormat.KeySize)
	}
	if keyFormat.Params.DerivedKeySize != keySize {
		return fmt.Errorf("incorrect derived key size, expect %d, got %d", keySize, keyFormat.Params.DerivedKeySize)
	}
	if keyFormat.Params.CiphertextSegmentSize != ciphertextSegmentSize {
		return fmt.Errorf("incorrect ciphertext segment size, expect %d, got %d", ciphertextSegmentSize, keyFormat.Params.CiphertextSegmentSize)
	}
	if keyFormat.Params.HkdfHashType != hkdfHashType {
		return fmt.Errorf("incorrect HKDF hash type, expect %s, got %s", keyFormat.Params.HkdfHashType.String(), hkdfHashType.String())
	}
	return nil
}

func TestAESCTRHMACKeyTemplates(t *testing.T) {
	testcases := []struct {
		name                  string
		template              *tinkpb.KeyTemplate
		keySize               uint32
		hkdfHashType          commonpb.HashType
		tagAlg                commonpb.HashType
		tagSize               uint32
		ciphertextSegmentSize uint32
	}{
		{
			name:                  "AES128CTRHMACSHA256Segment4KBKeyTemplate",
			template:              streamingaead.AES128CTRHMACSHA256Segment4KBKeyTemplate(),
			keySize:               16,
			hkdfHashType:          commonpb.HashType_SHA256,
			tagAlg:                commonpb.HashType_SHA256,
			tagSize:               32,
			ciphertextSegmentSize: 4096,
		},
		{
			name:                  "AES128CTRHMACSHA256Segment1MBKeyTemplate",
			template:              streamingaead.AES128CTRHMACSHA256Segment1MBKeyTemplate(),
			keySize:               16,
			hkdfHashType:          commonpb.HashType_SHA256,
			tagAlg:                commonpb.HashType_SHA256,
			tagSize:               32,
			ciphertextSegmentSize: 1048576,
		},
		{
			name:                  "AES256CTRHMACSHA256Segment4KBKeyTemplate",
			template:              streamingaead.AES256CTRHMACSHA256Segment4KBKeyTemplate(),
			keySize:               32,
			hkdfHashType:          commonpb.HashType_SHA256,
			tagAlg:                commonpb.HashType_SHA256,
			tagSize:               32,
			ciphertextSegmentSize: 4096,
		},
		{
			name:                  "AES256CTRHMACSHA256Segment1MBKeyTemplate",
			template:              streamingaead.AES256CTRHMACSHA256Segment1MBKeyTemplate(),
			keySize:               32,
			hkdfHashType:          commonpb.HashType_SHA256,
			tagAlg:                commonpb.HashType_SHA256,
			tagSize:               32,
			ciphertextSegmentSize: 1048576,
		},
	}
	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			err := checkAESCTRHMACKeyTemplate(
				tc.template,
				tc.keySize,
				tc.hkdfHashType,
				tc.tagAlg,
				tc.tagSize,
				tc.ciphertextSegmentSize,
				tinkpb.OutputPrefixType_RAW,
			)
			if err != nil {
				t.Error(err)
			}
		})
	}
}

func checkAESCTRHMACKeyTemplate(
	template *tinkpb.KeyTemplate,
	keySize uint32,
	hkdfHashType commonpb.HashType,
	tagAlg commonpb.HashType,
	tagSize uint32,
	ciphertextSegmentSize uint32,
	outputPrefixType tinkpb.OutputPrefixType,
) error {
	if template.TypeUrl != testutil.AESCTRHMACTypeURL {
		return fmt.Errorf("incorrect type url")
	}
	if template.OutputPrefixType != outputPrefixType {
		return fmt.Errorf("incorrect output prefix type")
	}
	keyFormat := new(ctrhmacpb.AesCtrHmacStreamingKeyFormat)
	err := proto.Unmarshal(template.Value, keyFormat)
	if err != nil {
		return fmt.Errorf("cannot deserialize key format: %s", err)
	}
	if keyFormat.KeySize != keySize {
		return fmt.Errorf("incorrect main key size, expect %d, got %d", keySize, keyFormat.KeySize)
	}
	if keyFormat.Params.DerivedKeySize != keySize {
		return fmt.Errorf("incorrect derived key size, expect %d, got %d", keySize, keyFormat.Params.DerivedKeySize)
	}
	if keyFormat.Params.HkdfHashType != hkdfHashType {
		return fmt.Errorf("incorrect HKDF hash type, expect %s, got %s", hkdfHashType.String(), keyFormat.Params.HkdfHashType.String())
	}
	if keyFormat.Params.HmacParams.Hash != tagAlg {
		return fmt.Errorf("incorrect tag algorithm, expect %s, got %s", tagAlg.String(), keyFormat.Params.HmacParams.Hash.String())
	}
	if keyFormat.Params.HmacParams.TagSize != tagSize {
		return fmt.Errorf("incorrect tag size, expect %d, got %d", tagSize, keyFormat.Params.HmacParams.TagSize)
	}
	if keyFormat.Params.CiphertextSegmentSize != ciphertextSegmentSize {
		return fmt.Errorf("incorrect ciphertext segment size, expect %d, got %d", ciphertextSegmentSize, keyFormat.Params.CiphertextSegmentSize)
	}
	return nil
}
