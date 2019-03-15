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

#include "tink/crypto_format.h"
#include "tink/util/status.h"
#include "tink/util/test_keyset_handle.h"

#import "proto/EciesAeadHkdf.pbobjc.h"
#import "proto/Tink.pbobjc.h"

#import "objc/TINKConfig.h"
#import "objc/TINKHybridConfig.h"
#import "objc/TINKHybridDecrypt.h"
#import "objc/TINKHybridDecryptFactory.h"
#import "objc/TINKHybridEncrypt.h"
#import "objc/TINKHybridEncryptFactory.h"
#import "objc/TINKKeysetHandle.h"
#import "objc/core/TINKKeysetHandle_Internal.h"
#import "objc/util/TINKStrings.h"
#import "objc/util/TINKTestHelpers.h"

using crypto::tink::TestKeysetHandle;

@interface TINKHybridDecryptFactoryTest : XCTestCase
@end

static TINKPBEciesAeadHkdfPrivateKey *getNewEciesPrivateKey() {
  return TINKGetEciesAesGcmHkdfTestKey(TINKPBEllipticCurveType_NistP256,
                                       TINKPBEcPointFormat_Uncompressed, TINKPBHashType_Sha256, 32);
}

@implementation TINKHybridDecryptFactoryTest

- (void)testEncryptWith:(TINKPBKeyset *)publicKeyset andDecryptWith:(TINKPBKeyset *)privateKeyset {
  NSError *error = nil;
  std::string serializedKeyset = TINKPBSerializeToString(privateKeyset, &error);
  XCTAssertNil(error);
  google::crypto::tink::Keyset ccPrivateKeyset;
  XCTAssertTrue(ccPrivateKeyset.ParseFromString(serializedKeyset));
  TINKKeysetHandle *privateKeysetHandle = [[TINKKeysetHandle alloc]
      initWithCCKeysetHandle:TestKeysetHandle::GetKeysetHandle(ccPrivateKeyset)];

  error = nil;
  serializedKeyset = TINKPBSerializeToString(publicKeyset, &error);
  XCTAssertNil(error);
  google::crypto::tink::Keyset ccPublicKeyset;
  XCTAssertTrue(ccPublicKeyset.ParseFromString(serializedKeyset));
  TINKKeysetHandle *publicKeysetHandle = [[TINKKeysetHandle alloc]
      initWithCCKeysetHandle:TestKeysetHandle::GetKeysetHandle(ccPublicKeyset)];

  // Get a HybridDecrypt primitive.
  error = nil;
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
  google::crypto::tink::Keyset keyset;
  TINKKeysetHandle *keysetHandle =
      [[TINKKeysetHandle alloc] initWithCCKeysetHandle:TestKeysetHandle::GetKeysetHandle(keyset)];
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
  NSError *error = nil;
  TINKHybridConfig *hybridConfig = [[TINKHybridConfig alloc] initWithError:&error];
  XCTAssertNotNil(hybridConfig);
  XCTAssertNil(error);

  XCTAssertTrue([TINKConfig registerConfig:hybridConfig error:&error]);
  XCTAssertNil(error);

  uint32_t keyId1 = 1;
  uint32_t keyId2 = 2;
  uint32_t keyId3 = 3;
  TINKPBEciesAeadHkdfPrivateKey *eciesKey1 = getNewEciesPrivateKey();
  TINKPBEciesAeadHkdfPrivateKey *eciesKey2 = getNewEciesPrivateKey();
  TINKPBEciesAeadHkdfPrivateKey *eciesKey3 = getNewEciesPrivateKey();

  NSString *privateKeyType = @"type.googleapis.com/google.crypto.tink.EciesAeadHkdfPrivateKey";
  TINKPBKeyset_Key *tinkPrivateKey =
      TINKCreateKey(privateKeyType, keyId1, eciesKey1, TINKPBOutputPrefixType_Tink,
                    TINKPBKeyStatusType_Enabled, TINKPBKeyData_KeyMaterialType_AsymmetricPrivate);
  TINKPBKeyset_Key *rawPrivateKey =
      TINKCreateKey(privateKeyType, keyId2, eciesKey2, TINKPBOutputPrefixType_Raw,
                    TINKPBKeyStatusType_Enabled, TINKPBKeyData_KeyMaterialType_AsymmetricPrivate);
  TINKPBKeyset_Key *legacyPrivateKey =
      TINKCreateKey(privateKeyType, keyId3, eciesKey3, TINKPBOutputPrefixType_Legacy,
                    TINKPBKeyStatusType_Enabled, TINKPBKeyData_KeyMaterialType_AsymmetricPrivate);

  NSString *publicKeyType = @"type.googleapis.com/google.crypto.tink.EciesAeadHkdfPublicKey";
  TINKPBKeyset_Key *tinkPublicKey =
      TINKCreateKey(publicKeyType, keyId1, eciesKey1.publicKey, TINKPBOutputPrefixType_Tink,
                    TINKPBKeyStatusType_Enabled, TINKPBKeyData_KeyMaterialType_AsymmetricPublic);
  TINKPBKeyset_Key *rawPublicKey =
      TINKCreateKey(publicKeyType, keyId2, eciesKey2.publicKey, TINKPBOutputPrefixType_Raw,
                    TINKPBKeyStatusType_Enabled, TINKPBKeyData_KeyMaterialType_AsymmetricPublic);
  TINKPBKeyset_Key *legacyPublicKey =
      TINKCreateKey(publicKeyType, keyId3, eciesKey3.publicKey, TINKPBOutputPrefixType_Legacy,
                    TINKPBKeyStatusType_Enabled, TINKPBKeyData_KeyMaterialType_AsymmetricPublic);

  // Encrypt with tink and decrypt with tink.
  TINKPBKeyset *privateKeyset = TINKCreateKeyset(tinkPrivateKey, rawPrivateKey, legacyPrivateKey);
  TINKPBKeyset *publicKeyset = TINKCreateKeyset(tinkPublicKey, rawPublicKey, legacyPublicKey);
  [self testEncryptWith:publicKeyset andDecryptWith:privateKeyset];

  // Encrypt with raw and decrypt with raw.
  privateKeyset = TINKCreateKeyset(rawPrivateKey, tinkPrivateKey, legacyPrivateKey);
  publicKeyset = TINKCreateKeyset(rawPublicKey, tinkPublicKey, legacyPublicKey);
  [self testEncryptWith:publicKeyset andDecryptWith:privateKeyset];

  // Encrypt with legacy and decrypt with legacy
  privateKeyset = TINKCreateKeyset(legacyPrivateKey, tinkPrivateKey, rawPrivateKey);
  publicKeyset = TINKCreateKeyset(legacyPublicKey, tinkPublicKey, rawPublicKey);
  [self testEncryptWith:publicKeyset andDecryptWith:privateKeyset];

  // Encrypt with tink as primary, decrypt with raw as primary.
  publicKeyset = TINKCreateKeyset(tinkPublicKey, legacyPublicKey, rawPublicKey);
  privateKeyset = TINKCreateKeyset(rawPrivateKey, tinkPrivateKey, legacyPrivateKey);
  [self testEncryptWith:publicKeyset andDecryptWith:privateKeyset];

  // Encrypt with raw as primary, decrypt with tink as primary.
  publicKeyset = TINKCreateKeyset(rawPublicKey, tinkPublicKey, legacyPublicKey);
  privateKeyset = TINKCreateKeyset(tinkPrivateKey, rawPrivateKey, legacyPrivateKey);
  [self testEncryptWith:publicKeyset andDecryptWith:privateKeyset];
}

@end
