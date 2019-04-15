/**
 * Copyright 2017 Google Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 **************************************************************************
 */

#import "objc/TINKAllConfig.h"

#import <XCTest/XCTest.h>

#include "proto/config.pb.h"

#import "objc/TINKConfig.h"
#import "objc/TINKRegistryConfig.h"
#import "objc/core/TINKRegistryConfig_Internal.h"
#import "objc/util/TINKStrings.h"

@interface TINKAllConfigTest : XCTestCase
@end

@implementation TINKAllConfigTest

- (void)test110Config {
  NSError *error = nil;
  TINKAllConfig *allConfig = [[TINKAllConfig alloc] initWithError:&error];
  XCTAssertNotNil(allConfig);
  XCTAssertNil(error);
  google::crypto::tink::RegistryConfig config = allConfig.ccConfig;

  XCTAssertEqual(config.entry_size(), 20);

  std::string hmac_key_type = "type.googleapis.com/google.crypto.tink.HmacKey";
  XCTAssertTrue("TinkMac" == config.entry(0).catalogue_name());
  XCTAssertTrue("Mac" == config.entry(0).primitive_name());
  XCTAssertTrue(hmac_key_type == config.entry(0).type_url());
  XCTAssertTrue(config.entry(0).new_key_allowed());
  XCTAssertEqual(config.entry(0).key_manager_version(), 0);

  std::string aes_ctr_hmac_aead_key_type =
      "type.googleapis.com/google.crypto.tink.AesCtrHmacAeadKey";
  XCTAssertTrue("TinkAead" == config.entry(1).catalogue_name());
  XCTAssertTrue("Aead" == config.entry(1).primitive_name());
  XCTAssertTrue(aes_ctr_hmac_aead_key_type == config.entry(1).type_url());
  XCTAssertTrue(config.entry(1).new_key_allowed());
  XCTAssertEqual(config.entry(1).key_manager_version(), 0);

  std::string aes_gcm_key_type = "type.googleapis.com/google.crypto.tink.AesGcmKey";
  XCTAssertTrue("TinkAead" == config.entry(2).catalogue_name());
  XCTAssertTrue("Aead" == config.entry(2).primitive_name());
  XCTAssertTrue(aes_gcm_key_type == config.entry(2).type_url());
  XCTAssertTrue(config.entry(2).new_key_allowed());
  XCTAssertEqual(config.entry(2).key_manager_version(), 0);

  std::string aes_gcm_siv_key_type = "type.googleapis.com/google.crypto.tink.AesGcmSivKey";
  XCTAssertTrue("TinkAead" == config.entry(3).catalogue_name());
  XCTAssertTrue("Aead" == config.entry(3).primitive_name());
  XCTAssertTrue(aes_gcm_siv_key_type == config.entry(3).type_url());
  XCTAssertTrue(config.entry(3).new_key_allowed());
  XCTAssertEqual(config.entry(3).key_manager_version(), 0);

  std::string aes_eax_key_type = "type.googleapis.com/google.crypto.tink.AesEaxKey";
  XCTAssertTrue("TinkAead" == config.entry(4).catalogue_name());
  XCTAssertTrue("Aead" == config.entry(4).primitive_name());
  XCTAssertTrue(aes_eax_key_type == config.entry(4).type_url());
  XCTAssertTrue(config.entry(4).new_key_allowed());
  XCTAssertEqual(config.entry(4).key_manager_version(), 0);

  std::string xchacha20_poly1305_key_type =
      "type.googleapis.com/google.crypto.tink.XChaCha20Poly1305Key";
  XCTAssertTrue("TinkAead" == config.entry(5).catalogue_name());
  XCTAssertTrue("Aead" == config.entry(5).primitive_name());
  XCTAssertTrue(xchacha20_poly1305_key_type == config.entry(5).type_url());
  XCTAssertTrue(config.entry(5).new_key_allowed());
  XCTAssertEqual(config.entry(5).key_manager_version(), 0);

  std::string kms_aead_key_type = "type.googleapis.com/google.crypto.tink.KmsAeadKey";
  XCTAssertTrue("TinkAead" == config.entry(6).catalogue_name());
  XCTAssertTrue("Aead" == config.entry(6).primitive_name());
  XCTAssertTrue(kms_aead_key_type == config.entry(6).type_url());
  XCTAssertTrue(config.entry(6).new_key_allowed());
  XCTAssertEqual(config.entry(6).key_manager_version(), 0);

  std::string kms_envelope_aead_key_type =
      "type.googleapis.com/google.crypto.tink.KmsEnvelopeAeadKey";
  XCTAssertTrue("TinkAead" == config.entry(7).catalogue_name());
  XCTAssertTrue("Aead" == config.entry(7).primitive_name());
  XCTAssertTrue(kms_envelope_aead_key_type == config.entry(7).type_url());
  XCTAssertTrue(config.entry(7).new_key_allowed());
  XCTAssertEqual(config.entry(7).key_manager_version(), 0);

  std::string ecies_hybrid_decrypt_key_type =
      "type.googleapis.com/google.crypto.tink.EciesAeadHkdfPrivateKey";
  XCTAssertTrue("TinkHybridDecrypt" == config.entry(8).catalogue_name());
  XCTAssertTrue("HybridDecrypt" == config.entry(8).primitive_name());
  XCTAssertTrue(ecies_hybrid_decrypt_key_type == config.entry(8).type_url());
  XCTAssertTrue(config.entry(8).new_key_allowed());
  XCTAssertEqual(config.entry(8).key_manager_version(), 0);

  std::string ecies_hybrid_encrypt_key_type =
      "type.googleapis.com/google.crypto.tink.EciesAeadHkdfPublicKey";
  XCTAssertTrue("TinkHybridEncrypt" == config.entry(9).catalogue_name());
  XCTAssertTrue("HybridEncrypt" == config.entry(9).primitive_name());
  XCTAssertTrue(ecies_hybrid_encrypt_key_type == config.entry(9).type_url());
  XCTAssertTrue(config.entry(9).new_key_allowed());
  XCTAssertEqual(config.entry(9).key_manager_version(), 0);

  std::string ecdsa_sign_key_type = "type.googleapis.com/google.crypto.tink.EcdsaPrivateKey";
  XCTAssertTrue("TinkPublicKeySign" == config.entry(10).catalogue_name());
  XCTAssertTrue("PublicKeySign" == config.entry(10).primitive_name());
  XCTAssertTrue(ecdsa_sign_key_type == config.entry(10).type_url());
  XCTAssertTrue(config.entry(10).new_key_allowed());
  XCTAssertEqual(config.entry(10).key_manager_version(), 0);

  std::string ecdsa_verify_key_type = "type.googleapis.com/google.crypto.tink.EcdsaPublicKey";
  XCTAssertTrue("TinkPublicKeyVerify" == config.entry(11).catalogue_name());
  XCTAssertTrue("PublicKeyVerify" == config.entry(11).primitive_name());
  XCTAssertTrue(ecdsa_verify_key_type == config.entry(11).type_url());
  XCTAssertTrue(config.entry(11).new_key_allowed());
  XCTAssertEqual(config.entry(11).key_manager_version(), 0);

  std::string ed25519_sign_key_type = "type.googleapis.com/google.crypto.tink.Ed25519PrivateKey";
  XCTAssertTrue("TinkPublicKeySign" == config.entry(12).catalogue_name());
  XCTAssertTrue("PublicKeySign" == config.entry(12).primitive_name());
  XCTAssertTrue(ed25519_sign_key_type == config.entry(12).type_url());
  XCTAssertTrue(config.entry(12).new_key_allowed());
  XCTAssertEqual(config.entry(12).key_manager_version(), 0);

  std::string ed25519_verify_key_type = "type.googleapis.com/google.crypto.tink.Ed25519PublicKey";
  XCTAssertTrue("TinkPublicKeyVerify" == config.entry(13).catalogue_name());
  XCTAssertTrue("PublicKeyVerify" == config.entry(13).primitive_name());
  XCTAssertTrue(ed25519_verify_key_type == config.entry(13).type_url());
  XCTAssertTrue(config.entry(13).new_key_allowed());
  XCTAssertEqual(config.entry(13).key_manager_version(), 0);

  std::string rsa_ssa_pss_sign_key_type =
      "type.googleapis.com/google.crypto.tink.RsaSsaPssPrivateKey";
  XCTAssertTrue("TinkPublicKeySign" == config.entry(14).catalogue_name());
  XCTAssertTrue("PublicKeySign" == config.entry(14).primitive_name());
  XCTAssertTrue(rsa_ssa_pss_sign_key_type == config.entry(14).type_url());
  XCTAssertTrue(config.entry(14).new_key_allowed());
  XCTAssertEqual(config.entry(14).key_manager_version(), 0);

  std::string rsa_ssa_pss_verify_key_type =
      "type.googleapis.com/google.crypto.tink.RsaSsaPssPublicKey";
  XCTAssertTrue("TinkPublicKeyVerify" == config.entry(15).catalogue_name());
  XCTAssertTrue("PublicKeyVerify" == config.entry(15).primitive_name());
  XCTAssertTrue(rsa_ssa_pss_verify_key_type == config.entry(15).type_url());
  XCTAssertTrue(config.entry(15).new_key_allowed());
  XCTAssertEqual(config.entry(15).key_manager_version(), 0);

  std::string rsa_ssa_pkcs1_sign_key_type =
      "type.googleapis.com/google.crypto.tink.RsaSsaPkcs1PrivateKey";
  XCTAssertTrue("TinkPublicKeySign" == config.entry(16).catalogue_name());
  XCTAssertTrue("PublicKeySign" == config.entry(16).primitive_name());
  XCTAssertTrue(rsa_ssa_pkcs1_sign_key_type == config.entry(16).type_url());
  XCTAssertTrue(config.entry(16).new_key_allowed());
  XCTAssertEqual(config.entry(16).key_manager_version(), 0);

  std::string rsa_ssa_pkcs1_verify_key_type =
      "type.googleapis.com/google.crypto.tink.RsaSsaPkcs1PublicKey";
  XCTAssertTrue("TinkPublicKeyVerify" == config.entry(17).catalogue_name());
  XCTAssertTrue("PublicKeyVerify" == config.entry(17).primitive_name());
  XCTAssertTrue(rsa_ssa_pkcs1_verify_key_type == config.entry(17).type_url());
  XCTAssertTrue(config.entry(17).new_key_allowed());
  XCTAssertEqual(config.entry(17).key_manager_version(), 0);

  std::string aes_siv_key_type = "type.googleapis.com/google.crypto.tink.AesSivKey";
  XCTAssertTrue("TinkDeterministicAead" == config.entry(18).catalogue_name());
  XCTAssertTrue("DeterministicAead" == config.entry(18).primitive_name());
  XCTAssertTrue(aes_siv_key_type == config.entry(18).type_url());
  XCTAssertTrue(config.entry(18).new_key_allowed());
  XCTAssertEqual(config.entry(18).key_manager_version(), 0);

  std::string aes_gcm_hkdf_streaming_key_type =
      "type.googleapis.com/google.crypto.tink.AesGcmHkdfStreamingKey";
  XCTAssertTrue("TinkStreamingAead" == config.entry(19).catalogue_name());
  XCTAssertTrue("StreamingAead" == config.entry(19).primitive_name());
  XCTAssertTrue(aes_gcm_hkdf_streaming_key_type == config.entry(19).type_url());
  XCTAssertTrue(config.entry(19).new_key_allowed());
  XCTAssertEqual(config.entry(19).key_manager_version(), 0);
}

- (void)testConfigRegistration {
  NSError *error = nil;
  TINKAllConfig *config = [[TINKAllConfig alloc] initWithError:&error];
  XCTAssertNotNil(config);
  XCTAssertNil(error);

  XCTAssertTrue([TINKConfig registerConfig:config error:&error]);
  XCTAssertNil(error);
}

@end
