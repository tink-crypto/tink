// Copyright 2020 Google LLC
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

package streamingaead

import (
	"fmt"

	"google.golang.org/protobuf/proto"
	ctrhmacpb "github.com/google/tink/go/proto/aes_ctr_hmac_streaming_go_proto"
	gcmhkdfpb "github.com/google/tink/go/proto/aes_gcm_hkdf_streaming_go_proto"
	commonpb "github.com/google/tink/go/proto/common_go_proto"
	hmacpb "github.com/google/tink/go/proto/hmac_go_proto"
	tinkpb "github.com/google/tink/go/proto/tink_go_proto"
)

// This file contains pre-generated KeyTemplates for streaming AEAD keys. One can use these templates
// to generate new Keysets.

// AES128GCMHKDF4KBKeyTemplate is a KeyTemplate that generates an AES-GCM key with the following parameters:
//   - Main key size: 16 bytes
//   - HKDF algo: HMAC-SHA256
//   - Size of AES-GCM derived keys: 16 bytes
//   - Ciphertext segment size: 4096 bytes
func AES128GCMHKDF4KBKeyTemplate() *tinkpb.KeyTemplate {
	return newAESGCMHKDFKeyTemplate(16, commonpb.HashType_SHA256, 16, 4096)
}

// AES128GCMHKDF1MBKeyTemplate is a KeyTemplate that generates an AES-GCM key with the following parameters:
//   - Main key size: 16 bytes
//   - HKDF algo: HMAC-SHA256
//   - Size of AES-GCM derived keys: 16 bytes
//   - Ciphertext segment size: 1048576 bytes (1 MB)
func AES128GCMHKDF1MBKeyTemplate() *tinkpb.KeyTemplate {
	return newAESGCMHKDFKeyTemplate(16, commonpb.HashType_SHA256, 16, 1048576)
}

// AES256GCMHKDF4KBKeyTemplate is a KeyTemplate that generates an AES-GCM key with the following parameters:
//   - Main key size: 32 bytes
//   - HKDF algo: HMAC-SHA256
//   - Size of AES-GCM derived keys: 32 bytes
//   - Ciphertext segment size: 4096 bytes
func AES256GCMHKDF4KBKeyTemplate() *tinkpb.KeyTemplate {
	return newAESGCMHKDFKeyTemplate(32, commonpb.HashType_SHA256, 32, 4096)
}

// AES256GCMHKDF1MBKeyTemplate is a KeyTemplate that generates an AES-GCM key with the following parameters:
//   - Main key size: 32 bytes
//   - HKDF algo: HMAC-SHA256
//   - Size of AES-GCM derived keys: 32 bytes
//   - Ciphertext segment size: 1048576 bytes (1 MB)
func AES256GCMHKDF1MBKeyTemplate() *tinkpb.KeyTemplate {
	return newAESGCMHKDFKeyTemplate(32, commonpb.HashType_SHA256, 32, 1048576)
}

// AES128CTRHMACSHA256Segment4KBKeyTemplate is a KeyTemplate that generates an
// AES-CTR-HMAC key with the following parameters:
//		- Main key size: 16 bytes
//		- HKDF algorthim: HMAC-SHA256
//		- AES-CTR derived key size: 16 bytes
//		- Tag algorithm: HMAC-SHA256
//		- Tag size: 32 bytes
//		- Ciphertext segment size: 4096 bytes (4 KB)
func AES128CTRHMACSHA256Segment4KBKeyTemplate() *tinkpb.KeyTemplate {
	return newAESCTRHMACKeyTemplate(16, commonpb.HashType_SHA256, 16, commonpb.HashType_SHA256, 32, 4096)
}

// AES128CTRHMACSHA256Segment1MBKeyTemplate is a KeyTemplate that generates an
// AES-CTR-HMAC key with the following parameters:
//		- Main key size: 16 bytes
//		- HKDF algorthim: HMAC-SHA256
//		- AES-CTR derived key size: 16 bytes
//		- Tag algorithm: HMAC-SHA256
//		- Tag size: 32 bytes
//		- Ciphertext segment size: 1048576 bytes (1 MB)
func AES128CTRHMACSHA256Segment1MBKeyTemplate() *tinkpb.KeyTemplate {
	return newAESCTRHMACKeyTemplate(16, commonpb.HashType_SHA256, 16, commonpb.HashType_SHA256, 32, 1048576)
}

// AES256CTRHMACSHA256Segment4KBKeyTemplate is a KeyTemplate that generates an
// AES-CTR-HMAC key with the following parameters:
//		- Main key size: 32 bytes
//		- HKDF algorthim: HMAC-SHA256
//		- AES-CTR derived key size: 32 bytes
//		- Tag algorithm: HMAC-SHA256
//		- Tag size: 32 bytes
//		- Ciphertext segment size: 4096 bytes (4 KB)
func AES256CTRHMACSHA256Segment4KBKeyTemplate() *tinkpb.KeyTemplate {
	return newAESCTRHMACKeyTemplate(32, commonpb.HashType_SHA256, 32, commonpb.HashType_SHA256, 32, 4096)
}

// AES256CTRHMACSHA256Segment1MBKeyTemplate is a KeyTemplate that generates an
// AES-CTR-HMAC key with the following parameters:
//		- Main key size: 32 bytes
//		- HKDF algorthim: HMAC-SHA256
//		- AES-CTR derived key size: 32 bytes
//		- Tag algorithm: HMAC-SHA256
//		- Tag size: 32 bytes
//		- Ciphertext segment size: 1048576 bytes (1 MB)
func AES256CTRHMACSHA256Segment1MBKeyTemplate() *tinkpb.KeyTemplate {
	return newAESCTRHMACKeyTemplate(32, commonpb.HashType_SHA256, 32, commonpb.HashType_SHA256, 32, 1048576)
}

// newAESGCMHKDFKeyTemplate creates a KeyTemplate containing a AesGcmHkdfStreamingKeyFormat with
// specified parameters.
func newAESGCMHKDFKeyTemplate(
	mainKeySize uint32,
	hkdfHashType commonpb.HashType,
	derivedKeySize uint32,
	ciphertextSegmentSize uint32,
) *tinkpb.KeyTemplate {
	serializedFormat, err := proto.Marshal(&gcmhkdfpb.AesGcmHkdfStreamingKeyFormat{
		KeySize: mainKeySize,
		Params: &gcmhkdfpb.AesGcmHkdfStreamingParams{
			CiphertextSegmentSize: ciphertextSegmentSize,
			DerivedKeySize:        derivedKeySize,
			HkdfHashType:          hkdfHashType,
		},
	})
	if err != nil {
		panic(fmt.Sprintf("failed to marshal key: %s", err))
	}
	return &tinkpb.KeyTemplate{
		TypeUrl:          aesGCMHKDFTypeURL,
		Value:            serializedFormat,
		OutputPrefixType: tinkpb.OutputPrefixType_RAW,
	}
}

// newAESCTRHMACKeyTemplate creates a KeyTemplate containing a
// AesCtrHmacStreamingKeyFormat with the specified parameters.
func newAESCTRHMACKeyTemplate(
	mainKeySize uint32,
	hkdfHashType commonpb.HashType,
	derivedKeySize uint32,
	tagAlg commonpb.HashType,
	tagSize uint32,
	ciphertextSegmentSize uint32,
) *tinkpb.KeyTemplate {
	serializedFormat, err := proto.Marshal(&ctrhmacpb.AesCtrHmacStreamingKeyFormat{
		KeySize: mainKeySize,
		Params: &ctrhmacpb.AesCtrHmacStreamingParams{
			CiphertextSegmentSize: ciphertextSegmentSize,
			DerivedKeySize:        derivedKeySize,
			HkdfHashType:          hkdfHashType,
			HmacParams: &hmacpb.HmacParams{
				Hash:    tagAlg,
				TagSize: tagSize,
			},
		},
	})
	if err != nil {
		panic(fmt.Sprintf("failed to marshal key: %s", err))
	}
	return &tinkpb.KeyTemplate{
		TypeUrl:          aesCTRHMACTypeURL,
		Value:            serializedFormat,
		OutputPrefixType: tinkpb.OutputPrefixType_RAW,
	}
}
