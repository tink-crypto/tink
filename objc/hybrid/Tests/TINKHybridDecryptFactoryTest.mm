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

#include "cc/crypto_format.h"
#include "cc/util/status.h"
#include "cc/util/test_util.h"

#import "proto/EciesAeadHkdf.pbobjc.h"
#import "proto/Tink.pbobjc.h"

#import "objc/TINKHybridDecrypt.h"
#import "objc/TINKHybridEncrypt.h"
#import "objc/TINKKeysetHandle.h"
#import "objc/core/TINKKeysetHandle_Internal.h"
#import "objc/hybrid/TINKEciesAeadHkdfPublicKeyManager.h"
#import "objc/hybrid/TINKHybridDecryptConfig.h"
#import "objc/hybrid/TINKHybridDecryptFactory.h"
#import "objc/hybrid/TINKHybridDecryptFactory.h"
#import "objc/util/TINKStrings.h"
#import "objc/util/TINKTestHelpers.h"

@interface TINKHybridDecryptFactoryTest : XCTestCase
@end

static TINKPBEciesAeadHkdfPrivateKey *getNewEciesPrivateKey() {
  return TINKGetEciesAesGcmHkdfTestKey(TINKPBEllipticCurveType_NistP256,
                                       TINKPBEcPointFormat_Uncompressed, TINKPBHashType_Sha256, 24);
}

static TINKPBKeyset *createTestKeyset(TINKPBEciesAeadHkdfPrivateKey *eciesKey1,
                                      TINKPBEciesAeadHkdfPrivateKey *eciesKey2,
                                      TINKPBEciesAeadHkdfPrivateKey *eciesKey3) {
  NSString *const keyType = @"type.googleapis.com/google.crypto.tink.EciesAeadHkdfPrivateKey";
  TINKPBKeyset *keyset = [[TINKPBKeyset alloc] init];

  uint32_t keyID1 = 1234543;
  TINKAddTinkKey(keyType, keyID1, eciesKey1, TINKPBKeyStatusType_Enabled,
                 TINKPBKeyData_KeyMaterialType_AsymmetricPrivate, keyset);

  uint32_t keyID2 = 726329;
  TINKAddRawKey(keyType, keyID2, eciesKey2, TINKPBKeyStatusType_Enabled,
                TINKPBKeyData_KeyMaterialType_AsymmetricPrivate, keyset);

  uint32_t keyID3 = 7213743;
  TINKAddTinkKey(keyType, keyID3, eciesKey3, TINKPBKeyStatusType_Enabled,
                 TINKPBKeyData_KeyMaterialType_AsymmetricPrivate, keyset);

  keyset.primaryKeyId = keyID3;
  return keyset;
}

static id<TINKHybridEncrypt> getEncryptPrimitive(TINKPBEciesAeadHkdfPrivateKey *eciesKey) {
  TINKEciesAeadHkdfPublicKeyManager *eciesKeyManager =
      [[TINKEciesAeadHkdfPublicKeyManager alloc] init];

  id<TINKHybridEncrypt> primitive =
      [eciesKeyManager primitiveFromKey:[eciesKey publicKey] error:nil];
  return primitive;
}

static NSData *encrypt(id<TINKHybridEncrypt> hybridEncrypt,
                       TINKKeysetHandle *keysetHandle,
                       uint32_t keyIndex,
                       NSData *plaintext,
                       NSData *context) {
  // Ciphertext is the result of concatenating outputPrefix with the encrypted data.
  NSMutableData *ciphertext = [NSMutableData data];

  // Get the key prefix using the C++ CryptoFormat API.
  // TODO(candrian): Update this to use the Obj-C API when it is implemented.
  std::string output_prefix =
      crypto::tink::CryptoFormat::get_output_prefix(
            keysetHandle.ccKeysetHandle->get_keyset().key(keyIndex)).ValueOrDie();
  NSData *outputPrefix = TINKStringToNSData(output_prefix);
  [ciphertext appendData:outputPrefix];

  NSData *result = [hybridEncrypt encrypt:plaintext withContextInfo:context error:nil];
  [ciphertext appendData:result];
  return ciphertext;
}

@implementation TINKHybridDecryptFactoryTest

- (void)testPrimitiveWithEmptyKeyset {
  google::crypto::tink::Keyset keyset;
  TINKKeysetHandle *keysetHandle =
      [[TINKKeysetHandle alloc] initWithCCKeysetHandle:crypto::tink::test::GetKeysetHandle(keyset)];
  XCTAssertNotNil(keysetHandle);

  NSError *error = nil;
  id<TINKHybridDecrypt> primitive =
      [TINKHybridDecryptFactory primitiveWithKeysetHandle:keysetHandle error:&error];

  XCTAssertNil(primitive);
  XCTAssertNotNil(error);
  XCTAssertEqual(error.code, crypto::tink::util::error::INVALID_ARGUMENT);
  NSDictionary *userInfo = [error userInfo];
  NSString *errorString = [userInfo objectForKey:NSLocalizedFailureReasonErrorKey];
  XCTAssertTrue([errorString containsString:@"at least one key"]);
}

- (void)testPrimitiveWithKeyset {
  [TINKHybridDecryptConfig registerStandardKeyTypes];

  // Create a test Keyset with 3 keys.
  TINKPBEciesAeadHkdfPrivateKey *eciesKey1 = getNewEciesPrivateKey();
  TINKPBEciesAeadHkdfPrivateKey *eciesKey2 = getNewEciesPrivateKey();
  TINKPBEciesAeadHkdfPrivateKey *eciesKey3 = getNewEciesPrivateKey();
  TINKPBKeyset *keyset = createTestKeyset(eciesKey1, eciesKey2, eciesKey3);
  google::crypto::tink::Keyset ccKeyset;
  NSError *error = nil;
  std::string serializedKeyset = TINKPBSerializeToString(keyset, &error);
  XCTAssertNil(error);
  XCTAssertTrue(ccKeyset.ParseFromString(serializedKeyset));
  // NOLINTNEXTLINE
  TINKKeysetHandle *keysetHandle =
      [[TINKKeysetHandle alloc] initWithCCKeysetHandle:crypto::tink::test::GetKeysetHandle(ccKeyset)];

  // Get a HybridDecrypt primitive using the test Keyset.
  error = nil;
  id<TINKHybridDecrypt> hybridDecrypt =
      [TINKHybridDecryptFactory primitiveWithKeysetHandle:keysetHandle error:&error];
  XCTAssertNotNil(hybridDecrypt);
  XCTAssertNil(error);

  NSData *const plaintext = [@"some plaintext" dataUsingEncoding:NSUTF8StringEncoding];
  NSData *const context = [@"some context info" dataUsingEncoding:NSUTF8StringEncoding];

  // Encrypt the plaintext using the two ECIES keys.
  id<TINKHybridEncrypt> hybridEncrypt1 = getEncryptPrimitive(eciesKey1);
  NSData *ciphertext1 = encrypt(hybridEncrypt1, keysetHandle, 0, plaintext, context);

  id<TINKHybridEncrypt> hybridEncrypt2 = getEncryptPrimitive(eciesKey2);
  NSData *ciphertext2 = encrypt(hybridEncrypt2, keysetHandle, 1, plaintext, context);

  // Decrypt ciphertext1.
  error = nil;
  NSData *result = [hybridDecrypt decrypt:ciphertext1 withContextInfo:context error:&error];
  XCTAssertNil(error);
  XCTAssertNotNil(result);
  XCTAssertTrue([result isEqualToData:plaintext]);

  // Decrypt ciphertext2.
  error = nil;
  result = [hybridDecrypt decrypt:ciphertext2 withContextInfo:context error:&error];
  XCTAssertNil(error);
  XCTAssertNotNil(result);
  XCTAssertTrue([result isEqualToData:plaintext]);

  // Decrypt ciphertext1 with bad context.
  error = nil;
  NSData *const badContext = [@"bad context" dataUsingEncoding:NSUTF8StringEncoding];
  result = [hybridDecrypt decrypt:ciphertext1 withContextInfo:badContext error:&error];
  XCTAssertNil(result);
  XCTAssertNotNil(error);
  XCTAssertEqual(error.code, crypto::tink::util::error::INVALID_ARGUMENT);

  NSDictionary *userInfo = [error userInfo];
  XCTAssertNotNil(userInfo);

  NSString *errorString = [userInfo objectForKey:NSLocalizedFailureReasonErrorKey];
  XCTAssertTrue([errorString containsString:@"decryption failed"]);
}

@end
