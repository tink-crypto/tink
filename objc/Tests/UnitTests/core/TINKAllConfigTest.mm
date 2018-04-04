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
#import "objc/TINKVersion.h"
#import "objc/core/TINKRegistryConfig_Internal.h"
#import "objc/util/TINKStrings.h"
#import "proto/Config.pbobjc.h"

@interface TINKAllConfigTest : XCTestCase
@end

@implementation TINKAllConfigTest

- (void)testConfigContents {
  NSString *publicKeySignKeyType = @"type.googleapis.com/google.crypto.tink.EcdsaPrivateKey";
  NSString *publicKeyVerifyKeyType = @"type.googleapis.com/google.crypto.tink.EcdsaPublicKey";
  NSString *hybridEncryptKeyType = @"type.googleapis.com/google.crypto.tink.EciesAeadHkdfPublicKey";
  NSString *hybridDecryptKeyType =
      @"type.googleapis.com/google.crypto.tink.EciesAeadHkdfPrivateKey";
  NSString *aesCtrHmacAeadKeyType = @"type.googleapis.com/google.crypto.tink.AesCtrHmacAeadKey";
  NSString *aesGcmKeyType = @"type.googleapis.com/google.crypto.tink.AesGcmKey";
  NSString *hmacKeyType = @"type.googleapis.com/google.crypto.tink.HmacKey";

  NSError *error = nil;
  TINKAllConfig *allConfig = [[TINKAllConfig alloc] initWithVersion:TINKVersion1_1_0 error:&error];
  XCTAssertNotNil(allConfig);
  XCTAssertNil(error);

  google::crypto::tink::RegistryConfig ccConfig = allConfig.ccConfig;
  std::string serializedConfig;
  XCTAssertTrue(ccConfig.SerializeToString(&serializedConfig));

  NSError *parseError = nil;
  TINKPBRegistryConfig *config =
      [TINKPBRegistryConfig parseFromData:TINKStringToNSData(serializedConfig) error:&parseError];
  XCTAssertNil(parseError);
  XCTAssertNotNil(config);

  XCTAssertTrue([config.entryArray[0].catalogueName isEqualToString:@"TinkMac"]);
  XCTAssertTrue([config.entryArray[0].primitiveName isEqualToString:@"Mac"]);
  XCTAssertTrue([config.entryArray[0].typeURL isEqualToString:hmacKeyType]);
  XCTAssertTrue(config.entryArray[0].newKeyAllowed);
  XCTAssertEqual(config.entryArray[0].keyManagerVersion, 0);

  XCTAssertTrue([config.entryArray[1].catalogueName isEqualToString:@"TinkAead"]);
  XCTAssertTrue([config.entryArray[1].primitiveName isEqualToString:@"Aead"]);
  XCTAssertTrue([config.entryArray[1].typeURL isEqualToString:aesCtrHmacAeadKeyType]);
  XCTAssertTrue(config.entryArray[1].newKeyAllowed);
  XCTAssertEqual(config.entryArray[1].keyManagerVersion, 0);

  XCTAssertTrue([config.entryArray[2].catalogueName isEqualToString:@"TinkAead"]);
  XCTAssertTrue([config.entryArray[2].primitiveName isEqualToString:@"Aead"]);
  XCTAssertTrue([config.entryArray[2].typeURL isEqualToString:aesGcmKeyType]);
  XCTAssertTrue(config.entryArray[2].newKeyAllowed);
  XCTAssertEqual(config.entryArray[2].keyManagerVersion, 0);

  XCTAssertTrue([config.entryArray[3].catalogueName isEqualToString:@"TinkHybridDecrypt"]);
  XCTAssertTrue([config.entryArray[3].primitiveName isEqualToString:@"HybridDecrypt"]);
  XCTAssertTrue([config.entryArray[3].typeURL isEqualToString:hybridDecryptKeyType]);
  XCTAssertTrue(config.entryArray[3].newKeyAllowed);
  XCTAssertEqual(config.entryArray[3].keyManagerVersion, 0);

  XCTAssertTrue([config.entryArray[4].catalogueName isEqualToString:@"TinkHybridEncrypt"]);
  XCTAssertTrue([config.entryArray[4].primitiveName isEqualToString:@"HybridEncrypt"]);
  XCTAssertTrue([config.entryArray[4].typeURL isEqualToString:hybridEncryptKeyType]);
  XCTAssertTrue(config.entryArray[4].newKeyAllowed);
  XCTAssertEqual(config.entryArray[4].keyManagerVersion, 0);

  XCTAssertTrue([config.entryArray[5].catalogueName isEqualToString:@"TinkPublicKeySign"]);
  XCTAssertTrue([config.entryArray[5].primitiveName isEqualToString:@"PublicKeySign"]);
  XCTAssertTrue([config.entryArray[5].typeURL isEqualToString:publicKeySignKeyType]);
  XCTAssertTrue(config.entryArray[5].newKeyAllowed);
  XCTAssertEqual(config.entryArray[5].keyManagerVersion, 0);

  XCTAssertTrue([config.entryArray[6].catalogueName isEqualToString:@"TinkPublicKeyVerify"]);
  XCTAssertTrue([config.entryArray[6].primitiveName isEqualToString:@"PublicKeyVerify"]);
  XCTAssertTrue([config.entryArray[6].typeURL isEqualToString:publicKeyVerifyKeyType]);
  XCTAssertTrue(config.entryArray[6].newKeyAllowed);
  XCTAssertEqual(config.entryArray[6].keyManagerVersion, 0);
}

- (void)testConfigRegistration {
  NSError *error = nil;
  TINKAllConfig *config = [[TINKAllConfig alloc] initWithVersion:TINKVersion1_1_0 error:&error];
  XCTAssertNotNil(config);
  XCTAssertNil(error);

  XCTAssertTrue([TINKConfig registerConfig:config error:&error]);
  XCTAssertNil(error);
}

@end
