/**
 * Copyright 2022 Google LLC
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

#import "TINKPublicKeySignFactory.h"
#import "TINKPublicKeyVerifyFactory.h"

#import <XCTest/XCTest.h>

#include <memory>
#include <string>
#include <utility>

#include "absl/strings/escaping.h"

#import "TINKAllConfig.h"
#import "TINKJSONKeysetReader.h"
#import "TINKKeysetHandle+Cleartext.h"
#import "TINKKeysetHandle.h"
#import "TINKPublicKeySign.h"
#import "TINKPublicKeyVerify.h"
#import "util/TINKStrings.h"

// The serialized keysets were generated with Tinkey:
// tinkey create-keyset --key-template ECDSA_P521 --out-format json \
//   | tinkey add-key --key-template ECDSA_P521 --out-format json \
//   | tinkey add-key --key-template ECDSA_P521 --out-format json
//
// After this, we converted it to a public keyset with:
// tinkey create-public-keyset --out-format json < previous_stdin
//
// Then we edited the private keyset to get only the 3rd key in the public keyset.
// (Plus automatic formatting)

constexpr absl::string_view kEcdsaPublicKeyset = R"json(
{
  "primaryKeyId": 1588647101,
  "key": [
    {
      "keyData": {
        "typeUrl": "type.googleapis.com/google.crypto.tink.EcdsaPublicKey",
        "value": "EgYIBBAEGAIaQgFLPqQQ0PC3pzkB95PixsKtcP6IBUqenHi3BafyD0wWL16JvYtWK5J1pFrFj0FK0WyY7F67gQWmWbz5gSoyBZX6kyJCAOAPAN14JQILzrIoWD9Rg1sV9AG45Sa0nR1VV570YUDycv73DDUbWSUjrmyumK3fUsk7Z/hLpK4yR+JsTeMRZbSB",
        "keyMaterialType": "ASYMMETRIC_PUBLIC"
      },
      "status": "ENABLED",
      "keyId": 1588647101,
      "outputPrefixType": "TINK"
    },
    {
      "keyData": {
        "typeUrl": "type.googleapis.com/google.crypto.tink.EcdsaPublicKey",
        "value": "EgYIBBAEGAIaQgDOp/Hpv7I/fp3A9IqpcY4jshNWfHNj6roxf62QviXEg19RUdWbd4eK+mHEWDGpp+XvA7X9bASLN4OEv4NhSkqnziJCAKI9ufXd2rQQjXboDfMFAtcgVim3L13TWP9kpGZ47v1SGV/niRZK0+RZxraXFXg/lT99Z3XTJtYvDL1NNG0IGLy8",
        "keyMaterialType": "ASYMMETRIC_PUBLIC"
      },
      "status": "ENABLED",
      "keyId": 1525489880,
      "outputPrefixType": "TINK"
    },
    {
      "keyData": {
        "typeUrl": "type.googleapis.com/google.crypto.tink.EcdsaPublicKey",
        "value": "EgYIBBAEGAIaQgGER6+b/6pXv2JqoxNWprDv8vAtDe4dzW33zODcPLe9W0efcn+FiTF5yi6jAlAc4bmN+hYAAr9bv5HDMafG9zuzGyJCAbRyxpNJAb+7APqT5x6Ad+e3yT+It9j7z6hgq1tNmt6im7VWLrWi/8mqDmycE0hzaNymFi8oQhMSNg9n98x+MjlZ",
        "keyMaterialType": "ASYMMETRIC_PUBLIC"
      },
      "status": "ENABLED",
      "keyId": 815459617,
      "outputPrefixType": "TINK"
    }
  ]
}
)json";

// Obtained with tinkey from the above; plus manual editing to split up the keyset.
constexpr absl::string_view kKeyThreePrivateKeyset = R"json(
{
  "primaryKeyId": 815459617,
  "key": [
    {
      "keyData": {
        "typeUrl": "type.googleapis.com/google.crypto.tink.EcdsaPrivateKey",
        "value": "EpABEgYIBBAEGAIaQgGER6+b/6pXv2JqoxNWprDv8vAtDe4dzW33zODcPLe9W0efcn+FiTF5yi6jAlAc4bmN+hYAAr9bv5HDMafG9zuzGyJCAbRyxpNJAb+7APqT5x6Ad+e3yT+It9j7z6hgq1tNmt6im7VWLrWi/8mqDmycE0hzaNymFi8oQhMSNg9n98x+MjlZGkIAginhUHiaOORuoRCCGfNhiWcnE3EC6WXVlgughJ2bxk8KvYGZ5x8NtP1m8Tw5Cno3LiOWUrHGHurFAxiV8udoOOo=",
        "keyMaterialType": "ASYMMETRIC_PRIVATE"
      },
      "status": "ENABLED",
      "keyId": 815459617,
      "outputPrefixType": "TINK"
    }
  ]
}
)json";

@interface TINKPublicKeySignVerifyFactoryTest : XCTestCase
@end

@implementation TINKPublicKeySignVerifyFactoryTest

+ (void)setUp {
  NSError *error = nil;
  TINKAllConfig *allConfig = [[TINKAllConfig alloc] initWithError:&error];
  XCTAssertNotNil(allConfig);
  XCTAssertNil(error);
}

- (void)testCreatePublicKeySign {
  NSError *error = nil;
  TINKJSONKeysetReader *reader = [[TINKJSONKeysetReader alloc]
      initWithSerializedKeyset:TINKStringViewToNSData(kKeyThreePrivateKeyset)
                         error:&error];
  XCTAssertNil(error, @"TINKJSONKeysetReader creation failed with %@", error);

  TINKKeysetHandle *handle =
      [[TINKKeysetHandle alloc] initCleartextKeysetHandleWithKeysetReader:reader error:&error];
  XCTAssertNil(error, @"TINKKeysetHandle creation failed with %@", error);

  id<TINKPublicKeySign> publicKeySign = [TINKPublicKeySignFactory primitiveWithKeysetHandle:handle
                                                                                      error:&error];
  XCTAssertNotNil(publicKeySign);
  XCTAssertNil(error, @"TINKPublicKeySign creation failed with %@", error);
}

- (void)testCreatePublicKeyVerify {
  NSError *error = nil;
  TINKJSONKeysetReader *reader = [[TINKJSONKeysetReader alloc]
      initWithSerializedKeyset:TINKStringViewToNSData(kEcdsaPublicKeyset)
                         error:&error];
  XCTAssertNil(error, @"TINKJSONKeysetReader creation failed with %@", error);

  TINKKeysetHandle *handle =
      [[TINKKeysetHandle alloc] initCleartextKeysetHandleWithKeysetReader:reader error:&error];
  XCTAssertNil(error, @"TINKKeysetHandle creation failed with %@", error);

  id<TINKPublicKeyVerify> publicKeyVerify =
      [TINKPublicKeyVerifyFactory primitiveWithKeysetHandle:handle error:&error];
  XCTAssertNotNil(publicKeyVerify);
  XCTAssertNil(error, @"TINKPublicKeyVerify creation failed with %@", error);
}

- (void)testSignThenVerify {
  NSError *error = nil;
  TINKJSONKeysetReader *privateReader = [[TINKJSONKeysetReader alloc]
      initWithSerializedKeyset:TINKStringViewToNSData(kKeyThreePrivateKeyset)
                         error:&error];
  TINKKeysetHandle *privateHandle =
      [[TINKKeysetHandle alloc] initCleartextKeysetHandleWithKeysetReader:privateReader
                                                                    error:&error];

  id<TINKPublicKeySign> publicKeySign =
      [TINKPublicKeySignFactory primitiveWithKeysetHandle:privateHandle error:&error];

  TINKJSONKeysetReader *publicReader = [[TINKJSONKeysetReader alloc]
      initWithSerializedKeyset:TINKStringViewToNSData(kEcdsaPublicKeyset)
                         error:&error];

  TINKKeysetHandle *publicHandle =
      [[TINKKeysetHandle alloc] initCleartextKeysetHandleWithKeysetReader:publicReader
                                                                    error:&error];

  id<TINKPublicKeyVerify> publicKeyVerify =
      [TINKPublicKeyVerifyFactory primitiveWithKeysetHandle:publicHandle error:&error];

  NSData *empty = [[NSData alloc] init];

  NSData *signature = [publicKeySign signatureForData:empty error:&error];
  XCTAssertNil(error, @"signatureForData failed with %@", error);

  BOOL verification = [publicKeyVerify verifySignature:signature forData:empty error:&error];
  XCTAssertTrue(verification);
  XCTAssertNil(error, @"verifySignature failed with %@", error);
}

/** Tests that changing the message makes the signature fail. */
- (void)testModifySignature_VerifyFails {
  NSError *error = nil;
  TINKJSONKeysetReader *privateReader = [[TINKJSONKeysetReader alloc]
      initWithSerializedKeyset:TINKStringViewToNSData(kKeyThreePrivateKeyset)
                         error:&error];
  TINKKeysetHandle *privateHandle =
      [[TINKKeysetHandle alloc] initCleartextKeysetHandleWithKeysetReader:privateReader
                                                                    error:&error];

  id<TINKPublicKeySign> publicKeySign =
      [TINKPublicKeySignFactory primitiveWithKeysetHandle:privateHandle error:&error];

  TINKJSONKeysetReader *publicReader = [[TINKJSONKeysetReader alloc]
      initWithSerializedKeyset:TINKStringViewToNSData(kEcdsaPublicKeyset)
                         error:&error];

  TINKKeysetHandle *publicHandle =
      [[TINKKeysetHandle alloc] initCleartextKeysetHandleWithKeysetReader:publicReader
                                                                    error:&error];

  id<TINKPublicKeyVerify> publicKeyVerify =
      [TINKPublicKeyVerifyFactory primitiveWithKeysetHandle:publicHandle error:&error];

  NSData *empty = [[NSData alloc] init];

  NSData *signature = [publicKeySign signatureForData:empty error:&error];
  XCTAssertNil(error, @"signatureForData failed with %@", error);

  NSData *wrongMessage = [NSData dataWithBytes:"hi" length:2];

  BOOL verification = [publicKeyVerify verifySignature:signature forData:wrongMessage error:&error];
  XCTAssertFalse(verification);
  XCTAssertNotNil(error, @"verifySignature failed with %@", error);
}

@end
