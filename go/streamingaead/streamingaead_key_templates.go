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

package streamingaead

import (
	"fmt"

	"github.com/golang/protobuf/proto"
	gcmhkdfpb "github.com/google/tink/go/proto/aes_gcm_hkdf_streaming_go_proto"
	commonpb "github.com/google/tink/go/proto/common_go_proto"
	tinkpb "github.com/google/tink/go/proto/tink_go_proto"
)

// This file contains pre-generated KeyTemplates for streaming AEAD keys. One can use these templates
// to generate new Keysets.

// AES128GCMHKDF4KBKeyTemplate is a KeyTemplate that generates an AES-GCM key with the following parameters:
//   - Main key size: 16 bytes
//   - HKDF algo: HMAC-SHA256
//   - Size of AES-GCM derived keys: 16 bytes
//   - Ciphertext segment size 4096 bytes
func AES128GCMHKDF4KBKeyTemplate() *tinkpb.KeyTemplate {
	return newAESGCMHKDFKeyTemplate(16, commonpb.HashType_SHA256, 16, 4096)
}

// AES256GCMHKDF4KBKeyTemplate is a KeyTemplate that generates an AES-GCM key with the following parameters:
//   - Main key size: 32 bytes
//   - HKDF algo: HMAC-SHA256
//   - Size of AES-GCM derived keys: 32 bytes
//   - Ciphertext segment size 4096 bytes
func AES256GCMHKDF4KBKeyTemplate() *tinkpb.KeyTemplate {
	return newAESGCMHKDFKeyTemplate(32, commonpb.HashType_SHA256, 32, 4096)
}

// newAESGCMHKDFKeyTemplate creates a KeyTemplate containing a AesGcmHkdfStreamingKeyFormat with
// specified parameters.
func newAESGCMHKDFKeyTemplate(
	mainKeySize uint32,
	hkdfHashType commonpb.HashType,
	derivedKeySize uint32,
	ciphertextSegmentSize uint32,
) *tinkpb.KeyTemplate {
	format := &gcmhkdfpb.AesGcmHkdfStreamingKeyFormat{
		KeySize: mainKeySize,
		Params: &gcmhkdfpb.AesGcmHkdfStreamingParams{
			CiphertextSegmentSize: ciphertextSegmentSize,
			DerivedKeySize:        derivedKeySize,
			HkdfHashType:          hkdfHashType,
		},
	}
	serializedFormat, err := proto.Marshal(format)
	if err != nil {
		panic(fmt.Sprintf("failed to marshal key: %s", err))
	}
	return &tinkpb.KeyTemplate{
		TypeUrl:          aesGCMHKDFTypeURL,
		Value:            serializedFormat,
		OutputPrefixType: tinkpb.OutputPrefixType_RAW,
	}
}
