// Copyright 2018 Google LLC
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

package aead

import (
	"fmt"

	"google.golang.org/protobuf/proto"
	"github.com/google/tink/go/internal/tinkerror"
	ctrpb "github.com/google/tink/go/proto/aes_ctr_go_proto"
	ctrhmacpb "github.com/google/tink/go/proto/aes_ctr_hmac_aead_go_proto"
	gcmpb "github.com/google/tink/go/proto/aes_gcm_go_proto"
	gcmsivpb "github.com/google/tink/go/proto/aes_gcm_siv_go_proto"
	commonpb "github.com/google/tink/go/proto/common_go_proto"
	hmacpb "github.com/google/tink/go/proto/hmac_go_proto"
	kmsenvpb "github.com/google/tink/go/proto/kms_envelope_go_proto"
	tinkpb "github.com/google/tink/go/proto/tink_go_proto"
)

// This file contains pre-generated KeyTemplates for AEAD keys. One can use these templates
// to generate new Keysets.

// AES128GCMKeyTemplate is a KeyTemplate that generates an AES-GCM key with the following parameters:
//   - Key size: 16 bytes
//   - Output prefix type: TINK
func AES128GCMKeyTemplate() *tinkpb.KeyTemplate {
	return createAESGCMKeyTemplate(16, tinkpb.OutputPrefixType_TINK)
}

// AES256GCMKeyTemplate is a KeyTemplate that generates an AES-GCM key with the following parameters:
//   - Key size: 32 bytes
//   - Output prefix type: TINK
func AES256GCMKeyTemplate() *tinkpb.KeyTemplate {
	return createAESGCMKeyTemplate(32, tinkpb.OutputPrefixType_TINK)
}

// AES256GCMNoPrefixKeyTemplate is a KeyTemplate that generates an AES-GCM key with the following parameters:
//   - Key size: 32 bytes
//   - Output prefix type: RAW
func AES256GCMNoPrefixKeyTemplate() *tinkpb.KeyTemplate {
	return createAESGCMKeyTemplate(32, tinkpb.OutputPrefixType_RAW)
}

// AES128GCMSIVKeyTemplate is a KeyTemplate that generates an AES-GCM-SIV key with the following parameters:
//   - Key size: 16 bytes
//   - Output prefix type: TINK
func AES128GCMSIVKeyTemplate() *tinkpb.KeyTemplate {
	return createAESGCMSIVKeyTemplate(16, tinkpb.OutputPrefixType_TINK)
}

// AES256GCMSIVKeyTemplate is a KeyTemplate that generates an AES-GCM-SIV key with the following parameters:
//   - Key size: 32 bytes
//   - Output prefix type: TINK
func AES256GCMSIVKeyTemplate() *tinkpb.KeyTemplate {
	return createAESGCMSIVKeyTemplate(32, tinkpb.OutputPrefixType_TINK)
}

// AES256GCMSIVNoPrefixKeyTemplate is a KeyTemplate that generates an AES-GCM key with the following parameters:
//   - Key size: 32 bytes
//   - Output prefix type: RAW
func AES256GCMSIVNoPrefixKeyTemplate() *tinkpb.KeyTemplate {
	return createAESGCMSIVKeyTemplate(32, tinkpb.OutputPrefixType_RAW)
}

// AES128CTRHMACSHA256KeyTemplate is a KeyTemplate that generates an AES-CTR-HMAC-AEAD key with the following parameters:
//   - AES key size: 16 bytes
//   - AES CTR IV size: 16 bytes
//   - HMAC key size: 32 bytes
//   - HMAC tag size: 16 bytes
//   - HMAC hash function: SHA256
func AES128CTRHMACSHA256KeyTemplate() *tinkpb.KeyTemplate {
	return createAESCTRHMACAEADKeyTemplate(16, 16, 32, 16, commonpb.HashType_SHA256)
}

// AES256CTRHMACSHA256KeyTemplate is a KeyTemplate that generates an AES-CTR-HMAC-AEAD key with the following parameters:
//   - AES key size: 32 bytes
//   - AES CTR IV size: 16 bytes
//   - HMAC key size: 32 bytes
//   - HMAC tag size: 32 bytes
//   - HMAC hash function: SHA256
func AES256CTRHMACSHA256KeyTemplate() *tinkpb.KeyTemplate {
	return createAESCTRHMACAEADKeyTemplate(32, 16, 32, 32, commonpb.HashType_SHA256)
}

// ChaCha20Poly1305KeyTemplate is a KeyTemplate that generates a CHACHA20_POLY1305 key.
func ChaCha20Poly1305KeyTemplate() *tinkpb.KeyTemplate {
	return &tinkpb.KeyTemplate{
		// Don't set value because KeyFormat is not required.
		TypeUrl:          chaCha20Poly1305TypeURL,
		OutputPrefixType: tinkpb.OutputPrefixType_TINK,
	}
}

// XChaCha20Poly1305KeyTemplate is a KeyTemplate that generates a XCHACHA20_POLY1305 key.
func XChaCha20Poly1305KeyTemplate() *tinkpb.KeyTemplate {
	return &tinkpb.KeyTemplate{
		// Don't set value because KeyFormat is not required.
		TypeUrl:          xChaCha20Poly1305TypeURL,
		OutputPrefixType: tinkpb.OutputPrefixType_TINK,
	}
}

// CreateKMSEnvelopeAEADKeyTemplate returns a key template that generates a
// KMSEnvelopeAEAD key for a given key encryption key (KEK) in a remote key
// management service (KMS).
//
// When performing encrypt operations, a data encryption key (DEK) is generated
// for each ciphertext.  The DEK is wrapped by the remote KMS using the KEK and
// stored alongside the ciphertext.
//
// dekTemplate must be a KeyTemplate for any of these Tink AEAD key types (any
// other key template will be rejected):
//   - AesCtrHmacAeadKey
//   - AesGcmKey
//   - ChaCha20Poly1305Key
//   - XChaCha20Poly1305
//   - AesGcmSivKey
//
// DEKs generated by this key template use the RAW output prefix to make them
// compatible with remote KMS encrypt/decrypt operations.
//
// Unlike other templates, when you generate new keys with this template, Tink
// does not generate new key material, but only creates a reference to the
// remote KEK.
//
// If either uri or dekTemplate contain invalid input, an error is returned.
//
// It is often not necessary to use this function. Instead, you can call
// kmsClient.GetAEAD to get a remote AEAD, and create an envelope AEAD using
// [NewKMSEnvelopeAEAD2].
//
// There is no need to call registry.RegisterKMSClient anymore.
func CreateKMSEnvelopeAEADKeyTemplate(uri string, dekTemplate *tinkpb.KeyTemplate) (*tinkpb.KeyTemplate, error) {
	if !isSupporedKMSEnvelopeDEK(dekTemplate.GetTypeUrl()) {
		return nil, fmt.Errorf("unsupported DEK key type %s. Only Tink AEAD key types are supported", dekTemplate.GetTypeUrl())
	}

	f := &kmsenvpb.KmsEnvelopeAeadKeyFormat{
		KekUri:      uri,
		DekTemplate: dekTemplate,
	}
	serializedFormat, err := proto.Marshal(f)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal key format: %s", err)
	}
	return &tinkpb.KeyTemplate{
		Value:            serializedFormat,
		TypeUrl:          kmsEnvelopeAEADTypeURL,
		OutputPrefixType: tinkpb.OutputPrefixType_RAW,
	}, nil
}

// KMSEnvelopeAEADKeyTemplate returns a KeyTemplate that generates a
// KMSEnvelopeAEAD key for a given key encryption key (KEK) in a remote key
// management service (KMS).
//
// If either uri or dekTemplate contain invalid input, program execution will
// be interrupted.
//
// Deprecated: Use [CreateKMSEnvelopeAEADKeyTemplate], which returns an error
// value instead of interrupting the program.
func KMSEnvelopeAEADKeyTemplate(uri string, dekTemplate *tinkpb.KeyTemplate) *tinkpb.KeyTemplate {
	t, err := CreateKMSEnvelopeAEADKeyTemplate(uri, dekTemplate)
	if err != nil {
		tinkerror.Fail(err.Error())
	}
	return t
}

// createAESGCMKeyTemplate creates a new AES-GCM key template with the given key
// size in bytes.
func createAESGCMKeyTemplate(keySize uint32, outputPrefixType tinkpb.OutputPrefixType) *tinkpb.KeyTemplate {
	format := &gcmpb.AesGcmKeyFormat{
		KeySize: keySize,
	}
	serializedFormat, err := proto.Marshal(format)
	if err != nil {
		tinkerror.Fail(fmt.Sprintf("failed to marshal key format: %s", err))
	}
	return &tinkpb.KeyTemplate{
		TypeUrl:          aesGCMTypeURL,
		Value:            serializedFormat,
		OutputPrefixType: outputPrefixType,
	}
}

// createAESGCMSIVKeyTemplate creates a new AES-GCM-SIV key template with the given key
// size in bytes.
func createAESGCMSIVKeyTemplate(keySize uint32, outputPrefixType tinkpb.OutputPrefixType) *tinkpb.KeyTemplate {
	format := &gcmsivpb.AesGcmSivKeyFormat{
		KeySize: keySize,
	}
	serializedFormat, err := proto.Marshal(format)
	if err != nil {
		tinkerror.Fail(fmt.Sprintf("failed to marshal key format: %s", err))
	}
	return &tinkpb.KeyTemplate{
		TypeUrl:          aesGCMSIVTypeURL,
		Value:            serializedFormat,
		OutputPrefixType: outputPrefixType,
	}
}

func createAESCTRHMACAEADKeyTemplate(aesKeySize, ivSize, hmacKeySize, tagSize uint32, hash commonpb.HashType) *tinkpb.KeyTemplate {
	format := &ctrhmacpb.AesCtrHmacAeadKeyFormat{
		AesCtrKeyFormat: &ctrpb.AesCtrKeyFormat{
			Params:  &ctrpb.AesCtrParams{IvSize: ivSize},
			KeySize: aesKeySize,
		},
		HmacKeyFormat: &hmacpb.HmacKeyFormat{
			Params:  &hmacpb.HmacParams{Hash: hash, TagSize: tagSize},
			KeySize: hmacKeySize,
		},
	}
	serializedFormat, err := proto.Marshal(format)
	if err != nil {
		tinkerror.Fail(fmt.Sprintf("failed to marshal key format: %s", err))
	}
	return &tinkpb.KeyTemplate{
		Value:            serializedFormat,
		TypeUrl:          aesCTRHMACAEADTypeURL,
		OutputPrefixType: tinkpb.OutputPrefixType_TINK,
	}
}
