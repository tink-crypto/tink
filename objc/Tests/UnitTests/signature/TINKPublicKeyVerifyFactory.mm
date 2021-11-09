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

#import "objc/TINKPublicKeyVerifyFactory.h"

#import <Foundation/Foundation.h>
#import <XCTest/XCTest.h>

#import "objc/TINKKeysetHandle.h"
#import "objc/TINKPublicKeySign.h"
#import "objc/TINKPublicKeySignFactory.h"
#import "objc/TINKPublicKeyVerify.h"
#import "objc/TINKPublicKeyVerifyFactory.h"
#import "objc/TINKSignatureConfig.h"
#import "objc/core/TINKKeysetHandle_Internal.h"
#import "objc/signature/TINKPublicKeyVerifyInternal.h"
#import "objc/util/TINKStrings.h"

#include "absl/status/status.h"
#include "tink/crypto_format.h"
#include "tink/keyset_handle.h"
#include "tink/signature/ecdsa_sign_key_manager.h"
#include "tink/signature/signature_config.h"
#include "tink/util/status.h"
#include "tink/util/test_keyset_handle.h"
#include "tink/util/test_util.h"
#include "proto/ecdsa.pb.h"
#include "proto/tink.pb.h"

using crypto::tink::EcdsaSignKeyManager;
using google::crypto::tink::EcdsaSignatureEncoding;
using crypto::tink::KeyFactory;
using crypto::tink::TestKeysetHandle;
using crypto::tink::test::AddRawKey;
using crypto::tink::test::AddTinkKey;
using google::crypto::tink::EcdsaPublicKey;
using google::crypto::tink::EcdsaPrivateKey;
using google::crypto::tink::EllipticCurveType;
using google::crypto::tink::HashType;
using google::crypto::tink::KeyData;
using google::crypto::tink::Keyset;
using google::crypto::tink::KeyStatusType;

static EcdsaPrivateKey GetNewEcdsaPrivateKey() {
  return crypto::tink::test::GetEcdsaTestPrivateKey(EllipticCurveType::NIST_P256, HashType::SHA256,
                                                    EcdsaSignatureEncoding::DER);
}

static EcdsaPublicKey GetEcdsaPublicKeyFromPrivate(EcdsaPrivateKey &privateKey) {
  return privateKey.public_key();
}

@interface TINKPublicKeyVerifyFactoryTest : XCTestCase
@end

static Keyset privateKeyset;
static Keyset publicKeyset;

@implementation TINKPublicKeyVerifyFactoryTest

+ (void)setUp {
  [super setUp];

  EcdsaPrivateKey keys[3] = {GetNewEcdsaPrivateKey(), GetNewEcdsaPrivateKey(),
                             GetNewEcdsaPrivateKey()};

  // Prepare a private keyset.
  std::string key_type = "type.googleapis.com/google.crypto.tink.EcdsaPrivateKey";

  uint32_t key_id_1 = 1234543;
  AddTinkKey(key_type, key_id_1, keys[0], KeyStatusType::ENABLED, KeyData::ASYMMETRIC_PUBLIC,
             &privateKeyset);

  uint32_t key_id_2 = 726329;
  AddTinkKey(key_type, key_id_2, keys[1], KeyStatusType::ENABLED, KeyData::ASYMMETRIC_PUBLIC,
             &privateKeyset);

  uint32_t key_id_3 = 7213743;
  AddTinkKey(key_type, key_id_3, keys[2], KeyStatusType::ENABLED, KeyData::ASYMMETRIC_PUBLIC,
             &privateKeyset);

  privateKeyset.set_primary_key_id(key_id_3);

  // Prepare the equivalent public keyset.
  std::string public_key_type = "type.googleapis.com/google.crypto.tink.EcdsaPublicKey";

  AddTinkKey(public_key_type, key_id_1, GetEcdsaPublicKeyFromPrivate(keys[0]),
             KeyStatusType::ENABLED, KeyData::ASYMMETRIC_PUBLIC, &publicKeyset);

  AddTinkKey(public_key_type, key_id_2, GetEcdsaPublicKeyFromPrivate(keys[1]),
             KeyStatusType::ENABLED, KeyData::ASYMMETRIC_PUBLIC, &publicKeyset);

  AddTinkKey(public_key_type, key_id_3, GetEcdsaPublicKeyFromPrivate(keys[2]),
             KeyStatusType::ENABLED, KeyData::ASYMMETRIC_PUBLIC, &publicKeyset);

  publicKeyset.set_primary_key_id(key_id_3);
}

- (void)testEmptyKeyset {
  Keyset keyset;
  TINKKeysetHandle *handle =
      [[TINKKeysetHandle alloc] initWithCCKeysetHandle:TestKeysetHandle::GetKeysetHandle(keyset)];
  XCTAssertNotNil(handle);

  NSError *error = nil;
  id<TINKPublicKeyVerify> publicKeyVerify =
      [TINKPublicKeyVerifyFactory primitiveWithKeysetHandle:handle error:&error];
  XCTAssertNil(publicKeyVerify);
  XCTAssertNotNil(error);
  XCTAssertEqual((absl::StatusCode)error.code, absl::StatusCode::kInvalidArgument);
  XCTAssertTrue([error.localizedFailureReason containsString:@"at least one key"]);
}

- (void)testPrimitive {
  NSError *error = nil;
  TINKSignatureConfig *signatureConfig = [[TINKSignatureConfig alloc] initWithError:&error];
  XCTAssertNotNil(signatureConfig);
  XCTAssertNil(error);

  TINKKeysetHandle *handlePrivate = [[TINKKeysetHandle alloc]
      initWithCCKeysetHandle:TestKeysetHandle::GetKeysetHandle(privateKeyset)];
  XCTAssertNotNil(handlePrivate);

  TINKKeysetHandle *handlePublic = [[TINKKeysetHandle alloc]
      initWithCCKeysetHandle:TestKeysetHandle::GetKeysetHandle(publicKeyset)];
  XCTAssertNotNil(handlePublic);

  id<TINKPublicKeySign> publicKeySign =
      [TINKPublicKeySignFactory primitiveWithKeysetHandle:handlePrivate error:&error];
  XCTAssertNotNil(publicKeySign);
  XCTAssertNil(error);

  // Sign something so we can test the verify primitive.
  NSData *data = [@"some data to sign" dataUsingEncoding:NSUTF8StringEncoding];
  NSData *signature = [publicKeySign signatureForData:data error:&error];
  XCTAssertNil(error);
  XCTAssertNotNil(signature);

  id<TINKPublicKeyVerify> publicKeyVerify =
      [TINKPublicKeyVerifyFactory primitiveWithKeysetHandle:handlePublic error:&error];
  XCTAssertNotNil(publicKeyVerify);
  XCTAssertNil(error);
  TINKPublicKeyVerifyInternal *publicKeyVerifyInternal =
      (TINKPublicKeyVerifyInternal *)publicKeyVerify;
  XCTAssertTrue(publicKeyVerifyInternal.ccPublicKeyVerify != NULL);

  // Test verification.
  XCTAssertTrue([publicKeyVerify verifySignature:signature forData:data error:&error]);
  XCTAssertNil(error);

  // Flip every bit of the signature.
  const char *signatureBytes = (const char *)signature.bytes;
  for (NSUInteger byteIndex = 0; byteIndex < signature.length; byteIndex++) {
    const char currentByte = signatureBytes[byteIndex];

    for (NSUInteger bitIndex = 0; bitIndex < 8; bitIndex++) {
      // Flip every bit on this byte.
      char flippedByte = (currentByte ^ (1 << bitIndex));
      XCTAssertTrue(flippedByte != currentByte);

      // Replace the mutated byte in the original data.
      NSMutableData *mutableSignature = signature.mutableCopy;
      char *mutableBytes = (char *)mutableSignature.mutableBytes;
      mutableBytes[byteIndex] = flippedByte;

      error = nil;
      XCTAssertFalse([mutableSignature isEqualToData:signature]);
      XCTAssertFalse([publicKeyVerify verifySignature:mutableSignature forData:data error:&error]);
      XCTAssertEqual((absl::StatusCode)error.code, absl::StatusCode::kInvalidArgument);
      XCTAssertTrue([error.localizedFailureReason containsString:@"Invalid signature."]);
    }
  }

  // Flip every bit of the data.
  const char *dataBytes = (const char *)data.bytes;
  for (NSUInteger byteIndex = 0; byteIndex < data.length; byteIndex++) {
    const char currentByte = dataBytes[byteIndex];

    for (NSUInteger bitIndex = 0; bitIndex < 8; bitIndex++) {
      // Flip every bit on this byte.
      char flippedByte = (currentByte ^ (1 << bitIndex));
      XCTAssertTrue(flippedByte != currentByte);

      // Replace the mutated byte in the original data.
      NSMutableData *mutableData = data.mutableCopy;
      char *mutableBytes = (char *)mutableData.mutableBytes;
      mutableBytes[byteIndex] = flippedByte;

      error = nil;
      XCTAssertFalse([mutableData isEqualToData:data]);
      XCTAssertFalse([publicKeyVerify verifySignature:signature forData:mutableData error:&error]);
      XCTAssertEqual((absl::StatusCode)error.code, absl::StatusCode::kInvalidArgument);
      XCTAssertTrue([error.localizedFailureReason containsString:@"Invalid signature."]);
    }
  }
}

@end
