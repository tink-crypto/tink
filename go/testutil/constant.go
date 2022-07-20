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

package testutil

const (
	// AEAD

	// AESCTRHMACAEADKeyVersion is the maximal version of AES-CTR-HMAC-AEAD keys that Tink supports.
	AESCTRHMACAEADKeyVersion = 0
	// AESCTRHMACAEADTypeURL is the type URL of AES-CTR-HMAC-AEAD keys that Tink supports.
	AESCTRHMACAEADTypeURL = "type.googleapis.com/google.crypto.tink.AesCtrHmacAeadKey"

	// AESGCMKeyVersion is the maximal version of AES-GCM keys.
	AESGCMKeyVersion = 0
	// AESGCMTypeURL is the type URL of AES-GCM keys that Tink supports.
	AESGCMTypeURL = "type.googleapis.com/google.crypto.tink.AesGcmKey"

	// AESGCMSIVKeyVersion is the maximal version of AES-GCM-SIV keys.
	AESGCMSIVKeyVersion = 0
	// AESGCMSIVTypeURL is the type URL of AES-GCM-SIV keys that Tink supports.
	AESGCMSIVTypeURL = "type.googleapis.com/google.crypto.tink.AesGcmSivKey"

	// ChaCha20Poly1305KeyVersion is the maximal version of ChaCha20Poly1305 keys that Tink supports.
	ChaCha20Poly1305KeyVersion = 0
	// ChaCha20Poly1305TypeURL is the type URL of ChaCha20Poly1305 keys.
	ChaCha20Poly1305TypeURL = "type.googleapis.com/google.crypto.tink.ChaCha20Poly1305Key"

	// KMSEnvelopeAEADKeyVersion is the maximal version of KMSEnvelopeAEAD keys that Tink supports.
	KMSEnvelopeAEADKeyVersion = 0
	// KMSEnvelopeAEADTypeURL is the type URL of KMSEnvelopeAEAD keys.
	KMSEnvelopeAEADTypeURL = "type.googleapis.com/google.crypto.tink.KmsEnvelopeAeadKey"

	// XChaCha20Poly1305KeyVersion is the maximal version of XChaCha20Poly1305 keys that Tink supports.
	XChaCha20Poly1305KeyVersion = 0
	// XChaCha20Poly1305TypeURL is the type URL of XChaCha20Poly1305 keys.
	XChaCha20Poly1305TypeURL = "type.googleapis.com/google.crypto.tink.XChaCha20Poly1305Key"

	// EciesAeadHkdfPrivateKeyKeyVersion is the maximal version of keys that this key manager supports.
	EciesAeadHkdfPrivateKeyKeyVersion = 0

	// EciesAeadHkdfPrivateKeyTypeURL is the url that this key manager supports.
	EciesAeadHkdfPrivateKeyTypeURL = "type.googleapis.com/google.crypto.tink.EciesAeadHkdfPrivateKey"

	// EciesAeadHkdfPublicKeyKeyVersion is the maximal version of keys that this key manager supports.
	EciesAeadHkdfPublicKeyKeyVersion = 0

	// EciesAeadHkdfPublicKeyTypeURL is the url that this key manager supports.
	EciesAeadHkdfPublicKeyTypeURL = "type.googleapis.com/google.crypto.tink.EciesAeadHkdfPublicKey"

	// DeterministicAEAD

	// AESSIVKeyVersion is the maximal version of AES-SIV keys that Tink supports.
	AESSIVKeyVersion = 0
	// AESSIVTypeURL is the type URL of AES-SIV keys.
	AESSIVTypeURL = "type.googleapis.com/google.crypto.tink.AesSivKey"

	// MAC

	// HMACKeyVersion is the maximal version of HMAC keys that Tink supports.
	HMACKeyVersion = 0
	// HMACTypeURL is the type URL of HMAC keys.
	HMACTypeURL = "type.googleapis.com/google.crypto.tink.HmacKey"
	// AESCMACKeyVersion is the maximal version of HMAC keys that Tink supports.
	AESCMACKeyVersion = 0
	// AESCMACTypeURL is the type URL of AES-CMAC keys.
	AESCMACTypeURL = "type.googleapis.com/google.crypto.tink.AesCmacKey"

	// PRF Set

	// AESCMACPRFKeyVersion is the maximal version of AES CMAC PRF keys that Tink supports.
	AESCMACPRFKeyVersion = 0
	// AESCMACPRFTypeURL is the type URL of AES CMAC PRF keys.
	AESCMACPRFTypeURL = "type.googleapis.com/google.crypto.tink.AesCmacPrfKey"

	// HKDFPRFKeyVersion is the maximal version of HKDF PRF keys that Tink supports.
	HKDFPRFKeyVersion = 0
	// HKDFPRFTypeURL is the type URL of HKDF PRF keys.
	HKDFPRFTypeURL = "type.googleapis.com/google.crypto.tink.HkdfPrfKey"

	// HMACPRFKeyVersion is the maximal version of HMAC PRF keys that Tink supports.
	HMACPRFKeyVersion = 0
	// HMACPRFTypeURL is the type URL of HMAC PRF keys.
	HMACPRFTypeURL = "type.googleapis.com/google.crypto.tink.HmacPrfKey"

	// Digital signatures

	// ECDSASignerKeyVersion is the maximum version of ECDSA private keys that Tink supports.
	ECDSASignerKeyVersion = 0
	// ECDSASignerTypeURL is the type URL of ECDSA private keys.
	ECDSASignerTypeURL = "type.googleapis.com/google.crypto.tink.EcdsaPrivateKey"

	// ECDSAVerifierKeyVersion is the maximum version of ECDSA public keys that Tink supports.
	ECDSAVerifierKeyVersion = 0
	// ECDSAVerifierTypeURL is the type URL of ECDSA public keys.
	ECDSAVerifierTypeURL = "type.googleapis.com/google.crypto.tink.EcdsaPublicKey"

	// ED25519SignerKeyVersion is the maximum version of ED25519 private keys that Tink supports.
	ED25519SignerKeyVersion = 0
	// ED25519SignerTypeURL is the type URL of ED25519 private keys.
	ED25519SignerTypeURL = "type.googleapis.com/google.crypto.tink.Ed25519PrivateKey"

	// ED25519VerifierKeyVersion is the maximum version of ED25519 public keys that Tink supports.
	ED25519VerifierKeyVersion = 0
	// ED25519VerifierTypeURL is the type URL of ED25519 public keys.
	ED25519VerifierTypeURL = "type.googleapis.com/google.crypto.tink.Ed25519PublicKey"

	// Streaming AEAD

	// AESGCMHKDFKeyVersion is the maximum version of AES-GCM-HKDF keys that Tink supports.
	AESGCMHKDFKeyVersion = 0
	// AESGCMHKDFTypeURL is the type URL of AES-GCM-HKDF keys that Tink supports.
	AESGCMHKDFTypeURL = "type.googleapis.com/google.crypto.tink.AesGcmHkdfStreamingKey"

	// AESCTRHMACKeyVersion is the maximum version of AES-CTR-HMAC keys that Tink supports.
	AESCTRHMACKeyVersion = 0
	// AESCTRHMACTypeURL is the type URL of AES-CTR-HMAC keys that Tink supports.
	AESCTRHMACTypeURL = "type.googleapis.com/google.crypto.tink.AesCtrHmacStreamingKey"
)
