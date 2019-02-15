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

#import "objc/TINKDeterministicAeadConfig.h"

#import <XCTest/XCTest.h>

#import "objc/TINKConfig.h"
#import "objc/TINKRegistryConfig.h"
#import "objc/core/TINKRegistryConfig_Internal.h"

#include "tink/daead/deterministic_aead_config.h"
#include "proto/config.pb.h"

@interface TINKDeterministicAeadConfigTest : XCTestCase
@end

@implementation TINKDeterministicAeadConfigTest

- (void)testConfigContents {
  std::string aes_siv_key_type = "type.googleapis.com/google.crypto.tink.AesSivKey";

  NSError *error = nil;
  TINKDeterministicAeadConfig *aeadConfig =
      [[TINKDeterministicAeadConfig alloc] initWithError:&error];
  XCTAssertNotNil(aeadConfig);
  XCTAssertNil(error);

  google::crypto::tink::RegistryConfig config = aeadConfig.ccConfig;
  XCTAssertEqual(config.entry_size(), 1);

  XCTAssertTrue("TinkDeterministicAead" == config.entry(0).catalogue_name());
  XCTAssertTrue("DeterministicAead" == config.entry(0).primitive_name());
  XCTAssertTrue(aes_siv_key_type == config.entry(0).type_url());
  XCTAssertTrue(config.entry(0).new_key_allowed());
  XCTAssertEqual(config.entry(0).key_manager_version(), 0);

  // Registration of standard key types works.
  error = nil;
  XCTAssertTrue([TINKConfig registerConfig:aeadConfig error:&error]);
  XCTAssertNil(error);
}

@end
