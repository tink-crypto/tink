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

#include "absl/status/status.h"
#include "tink/util/status.h"
#include "tink/util/test_keyset_handle.h"
#include "tink/util/test_util.h"
#include "proto/ecies_aead_hkdf.pb.h"
#include "proto/tink.pb.h"

#import "objc/TINKConfig.h"
#import "objc/TINKHybridConfig.h"
#import "objc/TINKHybridEncrypt.h"
#import "objc/TINKHybridEncryptFactory.h"
#import "objc/TINKKeysetHandle.h"
#import "objc/core/TINKKeysetHandle_Internal.h"
#import "objc/util/TINKStrings.h"

using ::crypto::tink::TestKeysetHandle;
using ::crypto::tink::test::AddTinkKey;
using ::crypto::tink::test::AddRawKey;
using ::crypto::tink::test::AddLegacyKey;
using ::google::crypto::tink::EciesAeadHkdfPublicKey;
using ::google::crypto::tink::EcPointFormat;
using ::google::crypto::tink::EllipticCurveType;
using ::google::crypto::tink::HashType;
using ::google::crypto::tink::KeyData;
using ::google::crypto::tink::Keyset;
using ::google::crypto::tink::KeyStatusType;

@interface TINKHybridEncryptFactoryTest : XCTestCase
@end

static EciesAeadHkdfPublicKey getNewEciesPublicKey() {
  return crypto::tink::test::GetEciesAesGcmHkdfTestKey(
      EllipticCurveType::NIST_P256, EcPointFormat::UNCOMPRESSED, HashType::SHA256, 32).public_key();
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
  XCTAssertEqual((absl::StatusCode)error.code, absl::StatusCode::kInvalidArgument);
  NSDictionary *userInfo = [error userInfo];
  NSString *errorString = [userInfo objectForKey:NSLocalizedFailureReasonErrorKey];
  XCTAssertTrue([errorString containsString:@"at least one key"]);
}

- (void)testPrimitiveWithKeyset {
  // Prepare a Keyset.
  Keyset publicKeyset;
  std::string publicKeyType = "type.googleapis.com/google.crypto.tink.EciesAeadHkdfPublicKey";

  uint32_t keyId1 = 1234543;
  uint32_t keyId2 = 726329;
  uint32_t keyId3 = 7213743;
  EciesAeadHkdfPublicKey eciesKey1 = getNewEciesPublicKey();
  EciesAeadHkdfPublicKey eciesKey2 = getNewEciesPublicKey();
  EciesAeadHkdfPublicKey eciesKey3 = getNewEciesPublicKey();

  AddTinkKey(publicKeyType, keyId1, eciesKey1, KeyStatusType::ENABLED, KeyData::ASYMMETRIC_PUBLIC,
             &publicKeyset);
  AddRawKey(publicKeyType, keyId2, eciesKey2, KeyStatusType::ENABLED, KeyData::ASYMMETRIC_PUBLIC,
            &publicKeyset);
  AddLegacyKey(publicKeyType, keyId3, eciesKey3, KeyStatusType::ENABLED, KeyData::ASYMMETRIC_PUBLIC,
               &publicKeyset);

  publicKeyset.set_primary_key_id(keyId3);
  // Create a KeysetHandle and use it with the factory.
  TINKKeysetHandle *keysetHandle = [[TINKKeysetHandle alloc]
      initWithCCKeysetHandle:TestKeysetHandle::GetKeysetHandle(publicKeyset)];
  XCTAssertNotNil(keysetHandle);

  // Get a HybridEncrypt primitive.
  NSError *error = nil;
  id<TINKHybridEncrypt> primitive =
      [TINKHybridEncryptFactory primitiveWithKeysetHandle:keysetHandle error:&error];
  XCTAssertNil(error);
  XCTAssertNotNil(primitive);

  // Test the resulting HybridEncrypt-instance.
  NSData *plaintext = [@"some plaintext" dataUsingEncoding:NSUTF8StringEncoding];
  NSData *context = [@"some context info" dataUsingEncoding:NSUTF8StringEncoding];

  error = nil;
  NSData *result = [primitive encrypt:plaintext withContextInfo:context error:&error];
  XCTAssertNil(error);
  XCTAssertNotNil(result);
}

@end
