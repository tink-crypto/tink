/**
 * Copyright 2018 Google Inc.
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

#import "objc/TINKSignatureConfig.h"

#import <XCTest/XCTest.h>

#import "objc/TINKConfig.h"
#import "objc/TINKRegistryConfig.h"
#import "objc/core/TINKRegistryConfig_Internal.h"

#include "tink/signature/signature_config.h"
#include "proto/config.pb.h"

@interface TINKSignatureConfigTest : XCTestCase
@end

@implementation TINKSignatureConfigTest

- (void)testConfigContents {
  NSError *error = nil;
  TINKSignatureConfig *signatureConfig = [[TINKSignatureConfig alloc] initWithError:&error];
  XCTAssertNotNil(signatureConfig);
  XCTAssertNil(error);

  google::crypto::tink::RegistryConfig config = signatureConfig.ccConfig;
  XCTAssertEqual(config.entry_size(), 8);

  std::string sign_key_type = "type.googleapis.com/google.crypto.tink.EcdsaPrivateKey";
  std::string verify_key_type = "type.googleapis.com/google.crypto.tink.EcdsaPublicKey";
  XCTAssertTrue("TinkPublicKeySign" == config.entry(0).catalogue_name());
  XCTAssertTrue("PublicKeySign" == config.entry(0).primitive_name());
  XCTAssertTrue(sign_key_type == config.entry(0).type_url());
  XCTAssertTrue(config.entry(0).new_key_allowed());
  XCTAssertEqual(config.entry(0).key_manager_version(), 0);

  XCTAssertTrue("TinkPublicKeyVerify" == config.entry(1).catalogue_name());
  XCTAssertTrue("PublicKeyVerify" == config.entry(1).primitive_name());
  XCTAssertTrue(verify_key_type == config.entry(1).type_url());
  XCTAssertTrue(config.entry(1).new_key_allowed());
  XCTAssertEqual(config.entry(1).key_manager_version(), 0);

  sign_key_type = "type.googleapis.com/google.crypto.tink.Ed25519PrivateKey";
  verify_key_type = "type.googleapis.com/google.crypto.tink.Ed25519PublicKey";
  XCTAssertTrue("TinkPublicKeySign" == config.entry(2).catalogue_name());
  XCTAssertTrue("PublicKeySign" == config.entry(2).primitive_name());
  XCTAssertTrue(sign_key_type == config.entry(2).type_url());
  XCTAssertTrue(config.entry(2).new_key_allowed());
  XCTAssertEqual(config.entry(2).key_manager_version(), 0);

  XCTAssertTrue("TinkPublicKeyVerify" == config.entry(3).catalogue_name());
  XCTAssertTrue("PublicKeyVerify" == config.entry(3).primitive_name());
  XCTAssertTrue(verify_key_type == config.entry(3).type_url());
  XCTAssertTrue(config.entry(3).new_key_allowed());
  XCTAssertEqual(config.entry(3).key_manager_version(), 0);

  sign_key_type = "type.googleapis.com/google.crypto.tink.RsaSsaPssPrivateKey";
  verify_key_type = "type.googleapis.com/google.crypto.tink.RsaSsaPssPublicKey";
  XCTAssertTrue("TinkPublicKeySign" == config.entry(4).catalogue_name());
  XCTAssertTrue("PublicKeySign" == config.entry(4).primitive_name());
  XCTAssertTrue(sign_key_type == config.entry(4).type_url());
  XCTAssertTrue(config.entry(4).new_key_allowed());
  XCTAssertEqual(config.entry(4).key_manager_version(), 0);

  XCTAssertTrue("TinkPublicKeyVerify" == config.entry(5).catalogue_name());
  XCTAssertTrue("PublicKeyVerify" == config.entry(5).primitive_name());
  XCTAssertTrue(verify_key_type == config.entry(5).type_url());
  XCTAssertTrue(config.entry(5).new_key_allowed());
  XCTAssertEqual(config.entry(5).key_manager_version(), 0);

  sign_key_type = "type.googleapis.com/google.crypto.tink.RsaSsaPkcs1PrivateKey";
  verify_key_type = "type.googleapis.com/google.crypto.tink.RsaSsaPkcs1PublicKey";
  XCTAssertTrue("TinkPublicKeySign" == config.entry(6).catalogue_name());
  XCTAssertTrue("PublicKeySign" == config.entry(6).primitive_name());
  XCTAssertTrue(sign_key_type == config.entry(6).type_url());
  XCTAssertTrue(config.entry(6).new_key_allowed());
  XCTAssertEqual(config.entry(6).key_manager_version(), 0);

  XCTAssertTrue("TinkPublicKeyVerify" == config.entry(7).catalogue_name());
  XCTAssertTrue("PublicKeyVerify" == config.entry(7).primitive_name());
  XCTAssertTrue(verify_key_type == config.entry(7).type_url());
  XCTAssertTrue(config.entry(7).new_key_allowed());
  XCTAssertEqual(config.entry(7).key_manager_version(), 0);

  // Registration of standard key types works.
  error = nil;
  XCTAssertTrue([TINKConfig registerConfig:signatureConfig error:&error]);
  XCTAssertNil(error);
}

@end
