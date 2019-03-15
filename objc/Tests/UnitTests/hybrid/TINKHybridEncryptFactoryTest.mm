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

#import <XCTest/XCTest.h>

#include "tink/util/status.h"
#include "tink/util/test_keyset_handle.h"
#include "proto/tink.pb.h"

#import "proto/Common.pbobjc.h"
#import "proto/EciesAeadHkdf.pbobjc.h"
#import "proto/Tink.pbobjc.h"

#import "objc/TINKConfig.h"
#import "objc/TINKHybridConfig.h"
#import "objc/TINKHybridEncrypt.h"
#import "objc/TINKHybridEncryptFactory.h"
#import "objc/TINKKeysetHandle.h"
#import "objc/core/TINKKeysetHandle_Internal.h"
#import "objc/util/TINKStrings.h"
#import "objc/util/TINKTestHelpers.h"

using crypto::tink::TestKeysetHandle;

@interface TINKHybridEncryptFactoryTest : XCTestCase
@end

static TINKPBEciesAeadHkdfPublicKey *getNewEciesPublicKey() {
  TINKPBEciesAeadHkdfPrivateKey *eciesKey =
      TINKGetEciesAesGcmHkdfTestKey(TINKPBEllipticCurveType_NistP256,
                                    TINKPBEcPointFormat_Uncompressed, TINKPBHashType_Sha256, 32);
  return eciesKey.publicKey;
}

@implementation TINKHybridEncryptFactoryTest

- (void)testPrimitiveWithEmptyKeyset {
  google::crypto::tink::Keyset keyset;
  TINKKeysetHandle *keysetHandle =
      [[TINKKeysetHandle alloc] initWithCCKeysetHandle:TestKeysetHandle::GetKeysetHandle(keyset)];

  NSError *error = nil;
  id<TINKHybridEncrypt> primitive =
      [TINKHybridEncryptFactory primitiveWithKeysetHandle:keysetHandle error:&error];

  XCTAssertNil(primitive);
  XCTAssertNotNil(error);
  XCTAssertEqual(error.code, crypto::tink::util::error::INVALID_ARGUMENT);
  NSDictionary *userInfo = [error userInfo];
  NSString *errorString = [userInfo objectForKey:NSLocalizedFailureReasonErrorKey];
  XCTAssertTrue([errorString containsString:@"at least one key"]);
}

- (void)testPrimitiveWithKeyset {
  // Prepare a Keyset.
  TINKPBKeyset *keyset = [[TINKPBKeyset alloc] init];
  NSString *keyType = @"type.googleapis.com/google.crypto.tink.EciesAeadHkdfPublicKey";

  uint32_t key_id_1 = 1234543;
  TINKAddTinkKey(keyType, key_id_1, getNewEciesPublicKey(), TINKPBKeyStatusType_Enabled,
                 TINKPBKeyData_KeyMaterialType_AsymmetricPublic, keyset);

  uint32_t key_id_2 = 726329;
  TINKAddRawKey(keyType, key_id_2, getNewEciesPublicKey(), TINKPBKeyStatusType_Enabled,
                TINKPBKeyData_KeyMaterialType_AsymmetricPublic, keyset);

  uint32_t key_id_3 = 7213743;
  TINKAddTinkKey(keyType, key_id_3, getNewEciesPublicKey(), TINKPBKeyStatusType_Enabled,
                 TINKPBKeyData_KeyMaterialType_AsymmetricPublic, keyset);
  XCTAssertEqual(keyset.keyArray_Count, 3);

  keyset.primaryKeyId = key_id_3;

  // Initialize the registry.
  NSError *error = nil;
  TINKHybridConfig *hybridConfig = [[TINKHybridConfig alloc] initWithError:&error];
  XCTAssertNotNil(hybridConfig);
  XCTAssertNil(error);

  XCTAssertTrue([TINKConfig registerConfig:hybridConfig error:&error]);
  XCTAssertNil(error);

  std::string serializedKeyset = TINKPBSerializeToString(keyset, &error);
  XCTAssertNil(error);

  google::crypto::tink::Keyset ccKeyset;
  XCTAssertTrue(ccKeyset.ParseFromString(serializedKeyset));

  // Create a KeysetHandle and use it with the factory.
  TINKKeysetHandle *keysetHandle = [[TINKKeysetHandle alloc]
      initWithCCKeysetHandle:TestKeysetHandle::GetKeysetHandle(ccKeyset)];
  XCTAssertNotNil(keysetHandle);

  // Get a HybridEncrypt primitive.
  error = nil;
  id<TINKHybridEncrypt> primitive =
      [TINKHybridEncryptFactory primitiveWithKeysetHandle:keysetHandle error:&error];
  XCTAssertNotNil(primitive);
  XCTAssertNil(error);

  // Test the resulting HybridEncrypt-instance.
  NSData *plaintext = [@"some plaintext" dataUsingEncoding:NSUTF8StringEncoding];
  NSData *context = [@"some context info" dataUsingEncoding:NSUTF8StringEncoding];

  error = nil;
  NSData *result = [primitive encrypt:plaintext withContextInfo:context error:&error];
  XCTAssertNil(error);
  XCTAssertNotNil(result);
}

@end
