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
//
////////////////////////////////////////////////////////////////////////////////

package hybrid

import (
	"google.golang.org/protobuf/proto"
	"github.com/google/tink/go/aead"
	commonpb "github.com/google/tink/go/proto/common_go_proto"
	eciespb "github.com/google/tink/go/proto/ecies_aead_hkdf_go_proto"
	hpkepb "github.com/google/tink/go/proto/hpke_go_proto"
	tinkpb "github.com/google/tink/go/proto/tink_go_proto"
)

const hpkePrivateKeyTypeURL = "type.googleapis.com/google.crypto.tink.HpkePrivateKey"

// This file contains pre-generated KeyTemplates for HybridEncrypt keys. One can use these templates
// to generate new Keysets.

// DHKEM_X25519_HKDF_SHA256_HKDF_SHA256_AES_128_GCM_Key_Template creates a HPKE
// key template with
//  - KEM DHKEM_X25519_HKDF_SHA256,
//  - KDF HKDF_SHA256, and
//  - AEAD AES_128_GCM.
// It adds the 5-byte Tink prefix to ciphertexts.
func DHKEM_X25519_HKDF_SHA256_HKDF_SHA256_AES_128_GCM_Key_Template() *tinkpb.KeyTemplate {
	return createHPKEKeyTemplate(
		hpkepb.HpkeKem_DHKEM_X25519_HKDF_SHA256,
		hpkepb.HpkeKdf_HKDF_SHA256,
		hpkepb.HpkeAead_AES_128_GCM,
		tinkpb.OutputPrefixType_TINK,
	)
}

// DHKEM_X25519_HKDF_SHA256_HKDF_SHA256_AES_128_GCM_Raw_Key_Template creates a
// HPKE key template with
//  - KEM DHKEM_X25519_HKDF_SHA256,
//  - KDF HKDF_SHA256, and
//  - AEAD AES_128_GCM.
// It does not add a prefix to ciphertexts.
func DHKEM_X25519_HKDF_SHA256_HKDF_SHA256_AES_128_GCM_Raw_Key_Template() *tinkpb.KeyTemplate {
	return createHPKEKeyTemplate(
		hpkepb.HpkeKem_DHKEM_X25519_HKDF_SHA256,
		hpkepb.HpkeKdf_HKDF_SHA256,
		hpkepb.HpkeAead_AES_128_GCM,
		tinkpb.OutputPrefixType_RAW,
	)
}

// DHKEM_X25519_HKDF_SHA256_HKDF_SHA256_AES_256_GCM_Key_Template creates a HPKE
// key template with
//  - KEM DHKEM_X25519_HKDF_SHA256,
//  - KDF HKDF_SHA256, and
//  - AEAD AES_256_GCM.
// It adds the 5-byte Tink prefix to ciphertexts.
func DHKEM_X25519_HKDF_SHA256_HKDF_SHA256_AES_256_GCM_Key_Template() *tinkpb.KeyTemplate {
	return createHPKEKeyTemplate(
		hpkepb.HpkeKem_DHKEM_X25519_HKDF_SHA256,
		hpkepb.HpkeKdf_HKDF_SHA256,
		hpkepb.HpkeAead_AES_256_GCM,
		tinkpb.OutputPrefixType_TINK,
	)
}

// DHKEM_X25519_HKDF_SHA256_HKDF_SHA256_AES_256_GCM_Raw_Key_Template creates a
// HPKE key template with
//  - KEM DHKEM_X25519_HKDF_SHA256,
//  - KDF HKDF_SHA256, and
//  - AEAD AES_256_GCM.
// It does not add a prefix to ciphertexts.
func DHKEM_X25519_HKDF_SHA256_HKDF_SHA256_AES_256_GCM_Raw_Key_Template() *tinkpb.KeyTemplate {
	return createHPKEKeyTemplate(
		hpkepb.HpkeKem_DHKEM_X25519_HKDF_SHA256,
		hpkepb.HpkeKdf_HKDF_SHA256,
		hpkepb.HpkeAead_AES_256_GCM,
		tinkpb.OutputPrefixType_RAW,
	)
}

// DHKEM_X25519_HKDF_SHA256_HKDF_SHA256_CHACHA20_POLY1305_Key_Template creates a HPKE
// key template with
//  - KEM DHKEM_X25519_HKDF_SHA256,
//  - KDF HKDF_SHA256, and
//  - AEAD CHACHA20_POLY1305.
// It adds the 5-byte Tink prefix to ciphertexts.
func DHKEM_X25519_HKDF_SHA256_HKDF_SHA256_CHACHA20_POLY1305_Key_Template() *tinkpb.KeyTemplate {
	return createHPKEKeyTemplate(
		hpkepb.HpkeKem_DHKEM_X25519_HKDF_SHA256,
		hpkepb.HpkeKdf_HKDF_SHA256,
		hpkepb.HpkeAead_CHACHA20_POLY1305,
		tinkpb.OutputPrefixType_TINK,
	)
}

// DHKEM_X25519_HKDF_SHA256_HKDF_SHA256_CHACHA20_POLY1305_Raw_Key_Template creates a
// HPKE key template with
//  - KEM DHKEM_X25519_HKDF_SHA256,
//  - KDF HKDF_SHA256, and
//  - AEAD CHACHA20_POLY1305.
// It does not add a prefix to ciphertexts.
func DHKEM_X25519_HKDF_SHA256_HKDF_SHA256_CHACHA20_POLY1305_Raw_Key_Template() *tinkpb.KeyTemplate {
	return createHPKEKeyTemplate(
		hpkepb.HpkeKem_DHKEM_X25519_HKDF_SHA256,
		hpkepb.HpkeKdf_HKDF_SHA256,
		hpkepb.HpkeAead_CHACHA20_POLY1305,
		tinkpb.OutputPrefixType_RAW,
	)
}

// createHPKEKeyTemplate creates a new HPKE key template with the given parameters.
func createHPKEKeyTemplate(kem hpkepb.HpkeKem, kdf hpkepb.HpkeKdf, aead hpkepb.HpkeAead, outputPrefixType tinkpb.OutputPrefixType) *tinkpb.KeyTemplate {
	format := &hpkepb.HpkeKeyFormat{
		Params: &hpkepb.HpkeParams{
			Kem:  kem,
			Kdf:  kdf,
			Aead: aead,
		},
	}
	serializedFormat, _ := proto.Marshal(format)
	return &tinkpb.KeyTemplate{
		TypeUrl:          hpkePrivateKeyTypeURL,
		Value:            serializedFormat,
		OutputPrefixType: outputPrefixType,
	}
}

// ECIESHKDFAES128GCMKeyTemplate is a KeyTemplate that generates an ECDH P-256 and decapsulation key
// AES128-GCM key with the following parameters:
//  - KEM: ECDH over NIST P-256
//  - DEM: AES128-GCM
//  - KDF: HKDF-HMAC-SHA256 with an empty salt
func ECIESHKDFAES128GCMKeyTemplate() *tinkpb.KeyTemplate {
	empty := []byte{}
	return createECIESAEADHKDFKeyTemplate(commonpb.EllipticCurveType_NIST_P256, commonpb.HashType_SHA256, commonpb.EcPointFormat_UNCOMPRESSED, aead.AES128GCMKeyTemplate(), empty)
}

// ECIESHKDFAES128CTRHMACSHA256KeyTemplate is a KeyTemplate that generates an ECDH P-256 and
// decapsulation key AES128-CTR-HMAC-SHA256 with the following parameters:
//  - KEM: ECDH over NIST P-256
//  - DEM: AES128-CTR-HMAC-SHA256 with the following parameters
//      - AES key size: 16 bytes
//      - AES CTR IV size: 16 bytes
//      - HMAC key size: 32 bytes
//      - HMAC tag size: 16 bytes
//  - KDF: HKDF-HMAC-SHA256 with an empty salt
func ECIESHKDFAES128CTRHMACSHA256KeyTemplate() *tinkpb.KeyTemplate {
	empty := []byte{}
	return createECIESAEADHKDFKeyTemplate(commonpb.EllipticCurveType_NIST_P256, commonpb.HashType_SHA256, commonpb.EcPointFormat_UNCOMPRESSED, aead.AES128CTRHMACSHA256KeyTemplate(), empty)
}

// createEciesAEADHKDFKeyTemplate creates a new ECIES-AEAD-HKDF key template with the given key size
// in bytes.
func createECIESAEADHKDFKeyTemplate(c commonpb.EllipticCurveType, ht commonpb.HashType, ptfmt commonpb.EcPointFormat, dekT *tinkpb.KeyTemplate, salt []byte) *tinkpb.KeyTemplate {
	format := &eciespb.EciesAeadHkdfKeyFormat{
		Params: &eciespb.EciesAeadHkdfParams{
			KemParams: &eciespb.EciesHkdfKemParams{
				CurveType:    c,
				HkdfHashType: ht,
				HkdfSalt:     salt,
			},
			DemParams: &eciespb.EciesAeadDemParams{
				AeadDem: dekT,
			},
			EcPointFormat: ptfmt,
		},
	}
	serializedFormat, _ := proto.Marshal(format)
	return &tinkpb.KeyTemplate{
		TypeUrl:          eciesAEADHKDFPrivateKeyTypeURL,
		Value:            serializedFormat,
		OutputPrefixType: tinkpb.OutputPrefixType_TINK,
	}
}
