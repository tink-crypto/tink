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

  XCTAssertTrue(config.entry_size() == 10);

  std::string hmac_key_type = "type.googleapis.com/google.crypto.tink.HmacKey";
  XCTAssertTrue("TinkMac" == config.entry(0).catalogue_name());
  XCTAssertTrue("Mac" == config.entry(0).primitive_name());
  XCTAssertTrue(hmac_key_type == config.entry(0).type_url());
  XCTAssertTrue(config.entry(0).new_key_allowed());
  XCTAssertTrue(0 == config.entry(0).key_manager_version());

  std::string aes_ctr_hmac_aead_key_type =
      "type.googleapis.com/google.crypto.tink.AesCtrHmacAeadKey";
  XCTAssertTrue("TinkAead" == config.entry(1).catalogue_name());
  XCTAssertTrue("Aead" == config.entry(1).primitive_name());
  XCTAssertTrue(aes_ctr_hmac_aead_key_type == config.entry(1).type_url());
  XCTAssertTrue(config.entry(1).new_key_allowed());
  XCTAssertTrue(0 == config.entry(1).key_manager_version());

  std::string aes_gcm_key_type = "type.googleapis.com/google.crypto.tink.AesGcmKey";
  XCTAssertTrue("TinkAead" == config.entry(2).catalogue_name());
  XCTAssertTrue("Aead" == config.entry(2).primitive_name());
  XCTAssertTrue(aes_gcm_key_type == config.entry(2).type_url());
  XCTAssertTrue(config.entry(2).new_key_allowed());
  XCTAssertTrue(0 == config.entry(2).key_manager_version());

  std::string aes_eax_key_type = "type.googleapis.com/google.crypto.tink.AesEaxKey";
  XCTAssertTrue("TinkAead" == config.entry(3).catalogue_name());
  XCTAssertTrue("Aead" == config.entry(3).primitive_name());
  XCTAssertTrue(aes_eax_key_type == config.entry(3).type_url());
  XCTAssertTrue(config.entry(3).new_key_allowed());
  XCTAssertTrue(0 == config.entry(3).key_manager_version());

  std::string xchacha20_poly1305_key_type =
      "type.googleapis.com/google.crypto.tink.XChaCha20Poly1305Key";
  XCTAssertTrue("TinkAead" == config.entry(4).catalogue_name());
  XCTAssertTrue("Aead" == config.entry(4).primitive_name());
  XCTAssertTrue(xchacha20_poly1305_key_type == config.entry(4).type_url());
  XCTAssertTrue(config.entry(4).new_key_allowed());
  XCTAssertTrue(0 == config.entry(4).key_manager_version());

  std::string ecies_hybrid_decrypt_key_type =
      "type.googleapis.com/google.crypto.tink.EciesAeadHkdfPrivateKey";
  XCTAssertTrue("TinkHybridDecrypt" == config.entry(5).catalogue_name());
  XCTAssertTrue("HybridDecrypt" == config.entry(5).primitive_name());
  XCTAssertTrue(ecies_hybrid_decrypt_key_type == config.entry(5).type_url());
  XCTAssertTrue(config.entry(5).new_key_allowed());
  XCTAssertTrue(0 == config.entry(5).key_manager_version());

  std::string ecies_hybrid_encrypt_key_type =
      "type.googleapis.com/google.crypto.tink.EciesAeadHkdfPublicKey";
  XCTAssertTrue("TinkHybridEncrypt" == config.entry(6).catalogue_name());
  XCTAssertTrue("HybridEncrypt" == config.entry(6).primitive_name());
  XCTAssertTrue(ecies_hybrid_encrypt_key_type == config.entry(6).type_url());
  XCTAssertTrue(config.entry(6).new_key_allowed());
  XCTAssertTrue(0 == config.entry(6).key_manager_version());

  std::string ecdsa_sign_key_type = "type.googleapis.com/google.crypto.tink.EcdsaPrivateKey";
  XCTAssertTrue("TinkPublicKeySign" == config.entry(7).catalogue_name());
  XCTAssertTrue("PublicKeySign" == config.entry(7).primitive_name());
  XCTAssertTrue(ecdsa_sign_key_type == config.entry(7).type_url());
  XCTAssertTrue(config.entry(7).new_key_allowed());
  XCTAssertTrue(0 == config.entry(7).key_manager_version());

  std::string ecdsa_verify_key_type = "type.googleapis.com/google.crypto.tink.EcdsaPublicKey";
  XCTAssertTrue("TinkPublicKeyVerify" == config.entry(8).catalogue_name());
  XCTAssertTrue("PublicKeyVerify" == config.entry(8).primitive_name());
  XCTAssertTrue(ecdsa_verify_key_type == config.entry(8).type_url());
  XCTAssertTrue(config.entry(8).new_key_allowed());
  XCTAssertTrue(0 == config.entry(8).key_manager_version());

  std::string aes_siv_key_type = "type.googleapis.com/google.crypto.tink.AesSivKey";
  XCTAssertTrue("TinkDeterministicAead" == config.entry(9).catalogue_name());
  XCTAssertTrue("DeterministicAead" == config.entry(9).primitive_name());
  XCTAssertTrue(aes_siv_key_type == config.entry(9).type_url());
  XCTAssertTrue(config.entry(9).new_key_allowed());
  XCTAssertTrue(0 == config.entry(9).key_manager_version());
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
