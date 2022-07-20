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
#include "tink/crypto_format.h"
#include "tink/util/status.h"
#include "tink/util/test_keyset_handle.h"
#include "tink/util/test_util.h"
#include "proto/ecies_aead_hkdf.pb.h"
#include "proto/tink.pb.h"

#import "objc/TINKConfig.h"
#import "objc/TINKHybridConfig.h"
#import "objc/TINKHybridDecrypt.h"
#import "objc/TINKHybridDecryptFactory.h"
#import "objc/TINKHybridEncrypt.h"
#import "objc/TINKHybridEncryptFactory.h"
#import "objc/TINKKeysetHandle.h"
#import "objc/core/TINKKeysetHandle_Internal.h"
#import "objc/util/TINKStrings.h"

using ::crypto::tink::TestKeysetHandle;
using ::crypto::tink::test::AddTinkKey;
using ::crypto::tink::test::AddRawKey;
using ::crypto::tink::test::AddLegacyKey;
using ::google::crypto::tink::EciesAeadHkdfPrivateKey;
using ::google::crypto::tink::EcPointFormat;
using ::google::crypto::tink::EllipticCurveType;
using ::google::crypto::tink::HashType;
using ::google::crypto::tink::KeyData;
using ::google::crypto::tink::Keyset;
using ::google::crypto::tink::KeyStatusType;

@interface TINKHybridDecryptFactoryTest : XCTestCase
@end

static EciesAeadHkdfPrivateKey getNewEciesPrivateKey() {
  return crypto::tink::test::GetEciesAesGcmHkdfTestKey(
      EllipticCurveType::NIST_P256, EcPointFormat::UNCOMPRESSED, HashType::SHA256, 32);
}

@implementation TINKHybridDecryptFactoryTest

- (void)testEncryptWith:(Keyset *)publicKeyset andDecryptWith:(Keyset *)privateKeyset {
  TINKKeysetHandle *privateKeysetHandle = [[TINKKeysetHandle alloc]
      initWithCCKeysetHandle:TestKeysetHandle::GetKeysetHandle(*privateKeyset)];

  TINKKeysetHandle *publicKeysetHandle = [[TINKKeysetHandle alloc]
      initWithCCKeysetHandle:TestKeysetHandle::GetKeysetHandle(*publicKeyset)];

  // Get a HybridDecrypt primitive.
  NSError *error = nil;
  id<TINKHybridDecrypt> hybridDecrypt =
      [TINKHybridDecryptFactory primitiveWithKeysetHandle:privateKeysetHandle error:&error];
  XCTAssertNotNil(hybridDecrypt);
  XCTAssertNil(error);

  // Get a HybridEncrypt primitive.
  error = nil;
  id<TINKHybridEncrypt> primitive =
      [TINKHybridEncryptFactory primitiveWithKeysetHandle:publicKeysetHandle error:&error];
  XCTAssertNotNil(primitive);
  XCTAssertNil(error);

  NSData *const plaintext = [@"some plaintext" dataUsingEncoding:NSUTF8StringEncoding];
  NSData *const context = [@"some context info" dataUsingEncoding:NSUTF8StringEncoding];

  // Encrypt.
  error = nil;
  NSData *ciphertext = [primitive encrypt:plaintext withContextInfo:context error:&error];
  XCTAssertNil(error);
  XCTAssertNotNil(ciphertext);

  // Decrypt.
  error = nil;
  NSData *result = [hybridDecrypt decrypt:ciphertext withContextInfo:context error:&error];
  XCTAssertNil(error);
  XCTAssertNotNil(result);
  XCTAssertTrue([result isEqualToData:plaintext]);
}

- (void)testPrimitiveWithEmptyKeyset {
  NSError *error = nil;
  TINKHybridConfig *hybridConfig = [[TINKHybridConfig alloc] initWithError:&error];
  XCTAssertNotNil(hybridConfig);
  XCTAssertNil(error);

  google::crypto::tink::Keyset keyset;
  TINKKeysetHandle *keysetHandle =
      [[TINKKeysetHandle alloc] initWithCCKeysetHandle:TestKeysetHandle::GetKeysetHandle(keyset)];
  XCTAssertNotNil(keysetHandle);

  id<TINKHybridDecrypt> primitive =
      [TINKHybridDecryptFactory primitiveWithKeysetHandle:keysetHandle error:&error];

  XCTAssertNil(primitive);
  XCTAssertNotNil(error);
  XCTAssertEqual((absl::StatusCode)error.code, absl::StatusCode::kInvalidArgument);
  NSDictionary *userInfo = [error userInfo];
  NSString *errorString = [userInfo objectForKey:NSLocalizedFailureReasonErrorKey];
  XCTAssertTrue([errorString containsString:@"at least one key"]);
}

- (void)testPrimitiveWithKeyset {
  NSError *error = nil;
  TINKHybridConfig *hybridConfig = [[TINKHybridConfig alloc] initWithError:&error];
  XCTAssertNotNil(hybridConfig);
  XCTAssertNil(error);

  XCTAssertTrue([TINKConfig registerConfig:hybridConfig error:&error]);
  XCTAssertNil(error);

  uint32_t keyId1 = 1;
  uint32_t keyId2 = 2;
  uint32_t keyId3 = 3;
  EciesAeadHkdfPrivateKey eciesKey1 = getNewEciesPrivateKey();
  EciesAeadHkdfPrivateKey eciesKey2 = getNewEciesPrivateKey();
  EciesAeadHkdfPrivateKey eciesKey3 = getNewEciesPrivateKey();

  std::string privateKeyType = "type.googleapis.com/google.crypto.tink.EciesAeadHkdfPrivateKey";
  Keyset privateKeyset;
  AddTinkKey(privateKeyType, keyId1, eciesKey1, KeyStatusType::ENABLED, KeyData::ASYMMETRIC_PRIVATE,
             &privateKeyset);
  AddRawKey(privateKeyType, keyId2, eciesKey2, KeyStatusType::ENABLED, KeyData::ASYMMETRIC_PRIVATE,
            &privateKeyset);
  AddLegacyKey(privateKeyType, keyId3, eciesKey3, KeyStatusType::ENABLED,
               KeyData::ASYMMETRIC_PRIVATE, &privateKeyset);

  std::string publicKeyType = "type.googleapis.com/google.crypto.tink.EciesAeadHkdfPublicKey";
  Keyset publicKeyset;
  AddTinkKey(publicKeyType, keyId1, eciesKey1.public_key(), KeyStatusType::ENABLED,
             KeyData::ASYMMETRIC_PUBLIC, &publicKeyset);
  AddRawKey(publicKeyType, keyId2, eciesKey2.public_key(), KeyStatusType::ENABLED,
            KeyData::ASYMMETRIC_PUBLIC, &publicKeyset);
  AddLegacyKey(publicKeyType, keyId3, eciesKey3.public_key(), KeyStatusType::ENABLED,
               KeyData::ASYMMETRIC_PUBLIC, &publicKeyset);

  privateKeyset.set_primary_key_id(keyId1);
  publicKeyset.set_primary_key_id(keyId3);
  [self testEncryptWith:&publicKeyset andDecryptWith:&privateKeyset];

  privateKeyset.set_primary_key_id(keyId2);
  publicKeyset.set_primary_key_id(keyId3);
  [self testEncryptWith:&publicKeyset andDecryptWith:&privateKeyset];

  privateKeyset.set_primary_key_id(keyId3);
  publicKeyset.set_primary_key_id(keyId1);
  [self testEncryptWith:&publicKeyset andDecryptWith:&privateKeyset];
}

@end
