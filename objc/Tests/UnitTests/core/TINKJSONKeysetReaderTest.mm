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

#import "TINKJSONKeysetReader.h"

#import <XCTest/XCTest.h>

#include <memory>
#include <string>
#include <utility>

#import "TINKAead.h"
#import "TINKAeadFactory.h"
#import "TINKAllConfig.h"
#import "TINKKeysetHandle+Cleartext.h"
#import "TINKKeysetHandle.h"
#import "util/TINKStrings.h"

#include "absl/strings/escaping.h"

constexpr absl::string_view kSingleKeyAesGcmKeyset = R"json(
  {
    "primaryKeyId":1931667682,
    "key":[{
      "keyData":{
        "typeUrl":"type.googleapis.com/google.crypto.tink.AesGcmKey",
        "value":"GhD+9l0RANZjzZEZ8PDp7LRW",
        "keyMaterialType":"SYMMETRIC"},
      "status":"ENABLED",
      "keyId":1931667682,
      "outputPrefixType":"TINK"
    }]
  })json";


@interface TINKJSONKeysetReaderTest : XCTestCase
@end

@implementation TINKJSONKeysetReaderTest

+ (void)setUp {
  NSError *error = nil;
  TINKAllConfig *allConfig = [[TINKAllConfig alloc] initWithError:&error];
  XCTAssertNotNil(allConfig);
  XCTAssertNil(error);
}


- (void)testCreateKeysetHandle {
  NSData *serializedKeysetData = [NSData dataWithBytes:kSingleKeyAesGcmKeyset.data()
                                                length:kSingleKeyAesGcmKeyset.size()];
  NSError *error = nil;
  TINKJSONKeysetReader *reader =
      [[TINKJSONKeysetReader alloc] initWithSerializedKeyset:serializedKeysetData error:&error];
  XCTAssertNotNil(reader);
  XCTAssertNil(error, @"Initialization of TINKJSONKeysetReader failed with %@", error);

  TINKKeysetHandle *handle =
      [[TINKKeysetHandle alloc] initCleartextKeysetHandleWithKeysetReader:reader error:&error];
  XCTAssertNotNil(handle);
  XCTAssertNil(error, @"Initialization of TINKKeysetHandle failed with %@", error);
}

- (void)testCreateAead {
  NSData *serializedKeysetData = [NSData dataWithBytes:kSingleKeyAesGcmKeyset.data()
                                                length:kSingleKeyAesGcmKeyset.size()];
  NSError *error = nil;
  TINKJSONKeysetReader *reader =
      [[TINKJSONKeysetReader alloc] initWithSerializedKeyset:serializedKeysetData error:&error];

  TINKKeysetHandle *handle =
      [[TINKKeysetHandle alloc] initCleartextKeysetHandleWithKeysetReader:reader error:&error];

  id<TINKAead> aead = [TINKAeadFactory primitiveWithKeysetHandle:handle error:&error];
  XCTAssertNotNil(aead);
  XCTAssertNil(error, @"Aead creation failed with %@", error);

  NSString *kEmpty = @"";
  NSData *kEmptyData = [kEmpty dataUsingEncoding:NSUTF8StringEncoding];

  // Test vector for this key: encryption of the empty string with empty aad. Generated with Java.
  std::string kCiphertext = absl::HexStringToBytes(
      "017322e8e2c38b8d06b46b40010a6e2a19e572eb3e626ea64238bf9018fa61cbea");
  NSData *kCiphertextData = [NSData dataWithBytes:kCiphertext.data() length:kCiphertext.size()];
  NSData *computedPlaintext = [aead decrypt:kCiphertextData
                         withAdditionalData:kEmptyData
                                      error:&error];
  XCTAssertNil(error, @"Decryption failed with %@", error);
  XCTAssertEqual([computedPlaintext length], 0);
}

// If the keyset is not even json, we currently fail when initializing the TINKKeysetHandle.
- (void)testCreateKeysetHandle_brokenKeysetNotJson_fails {
  constexpr absl::string_view kKeysetNotJson = "This for sure isn't JSON }}}";

  NSData *serializedKeysetData = [NSData dataWithBytes:kKeysetNotJson.data()
                                                length:kKeysetNotJson.size()];
  NSError *error = nil;
  TINKJSONKeysetReader *reader =
      [[TINKJSONKeysetReader alloc] initWithSerializedKeyset:serializedKeysetData error:&error];
  XCTAssertNotNil(reader);
  XCTAssertNil(error, @"Initialization of TINKJSONKeysetReader failed with %@", error);

  (void)[[TINKKeysetHandle alloc] initCleartextKeysetHandleWithKeysetReader:reader error:&error];
  XCTAssertNotNil(error);
}

// If the keyset is broken e.g. because the primary doesn't exist, currently we only fail once we
// create the primitive.
- (void)testCreateKeysetHandle_brokenKeysetNoPrimary_fails {
  constexpr absl::string_view kKeysetWithNoPrimaryKey = R"json(
    {
      "primaryKeyId":1,
      "key":[{
        "keyData":{
          "typeUrl":"type.googleapis.com/google.crypto.tink.AesGcmKey",
          "value":"GhD+9l0RANZjzZEZ8PDp7LRW",
          "keyMaterialType":"SYMMETRIC"},
        "status":"ENABLED",
        "keyId":2,
        "outputPrefixType":"TINK"
      }]
    })json";

  NSData *serializedKeysetData = [NSData dataWithBytes:kKeysetWithNoPrimaryKey.data()
                                                length:kKeysetWithNoPrimaryKey.size()];
  NSError *error = nil;
  TINKJSONKeysetReader *reader =
      [[TINKJSONKeysetReader alloc] initWithSerializedKeyset:serializedKeysetData error:&error];
  XCTAssertNotNil(reader);
  XCTAssertNil(error, @"Initialization of TINKJSONKeysetReader failed with %@", error);

  TINKKeysetHandle *handle =
      [[TINKKeysetHandle alloc] initCleartextKeysetHandleWithKeysetReader:reader error:&error];
  XCTAssertNotNil(handle);
  XCTAssertNil(error, @"Initialization of TINKKeysetHandle failed with %@", error);

  (void)[TINKAeadFactory primitiveWithKeysetHandle:handle error:&error];
  XCTAssertNotNil(error);
}

// If the keyset is broken in that the key serialization is invalid, currently we fail when creating
// the aead.
- (void)testCreateKeysetHandle_brokenKeysetInvalidKey_fails {
  // gA== in base64 decodes to 0x80, a simple invalid serialized proto.
  constexpr absl::string_view kKeysetWithInvalidKey = R"json(
  {
    "primaryKeyId":1931667682,
    "key":[{
      "keyData":{
        "typeUrl":"type.googleapis.com/google.crypto.tink.AesGcmKey",
        "value":"gA==",
        "keyMaterialType":"SYMMETRIC"},
      "status":"ENABLED",
      "keyId":1931667682,
      "outputPrefixType":"TINK"
    }]
  })json";

  NSData *serializedKeysetData = [NSData dataWithBytes:kKeysetWithInvalidKey.data()
                                                length:kKeysetWithInvalidKey.size()];
  NSError *error = nil;
  TINKJSONKeysetReader *reader =
      [[TINKJSONKeysetReader alloc] initWithSerializedKeyset:serializedKeysetData error:&error];
  XCTAssertNotNil(reader);
  XCTAssertNil(error, @"Initialization of TINKJSONKeysetReader failed with %@", error);

  TINKKeysetHandle *handle =
      [[TINKKeysetHandle alloc] initCleartextKeysetHandleWithKeysetReader:reader error:&error];
  XCTAssertNotNil(handle);
  XCTAssertNil(error, @"Initialization of TINKKeysetHandle failed with %@", error);

  (void)[TINKAeadFactory primitiveWithKeysetHandle:handle error:&error];
  XCTAssertNotNil(error);
}

// Test that keysets with two keys work (by decrypting a non-primary ciphertext).
// Created from the above keyset with tinkey add-key --key_template=AES_128_GCM
- (void)testMultiKeyKeyset {
  constexpr absl::string_view kKeysetWithTwoKeys = R"json(
  {
    "primaryKeyId": 1617278036,
    "key": [
      {
        "keyData": {
          "typeUrl": "type.googleapis.com/google.crypto.tink.AesGcmKey",
          "value": "GhD+9l0RANZjzZEZ8PDp7LRW",
          "keyMaterialType": "SYMMETRIC"
        },
        "status": "ENABLED",
        "keyId": 1931667682,
        "outputPrefixType": "TINK"
      },
      {
        "keyData": {
          "typeUrl": "type.googleapis.com/google.crypto.tink.AesGcmKey",
          "value": "GhDqOTk9s1gXwupF4k9R9Cps",
          "keyMaterialType": "SYMMETRIC"
        },
        "status": "ENABLED",
        "keyId": 1617278036,
        "outputPrefixType": "RAW"
      }
    ]
  })json";

  // Get the AEAD from the kKeysetWithTwoKeys
  NSData *twoKeysSerializedKeysetData = [NSData dataWithBytes:kKeysetWithTwoKeys.data()
                                                length:kKeysetWithTwoKeys.size()];
  NSError *error = nil;
  TINKJSONKeysetReader *reader =
      [[TINKJSONKeysetReader alloc] initWithSerializedKeyset:twoKeysSerializedKeysetData
                                                       error:&error];
  XCTAssertNotNil(reader);
  XCTAssertNil(error, @"Initialization of TINKJSONKeysetReader failed with %@", error);

  TINKKeysetHandle *handle =
      [[TINKKeysetHandle alloc] initCleartextKeysetHandleWithKeysetReader:reader error:&error];
  XCTAssertNotNil(handle);
  XCTAssertNil(error, @"Initialization of TINKKeysetHandle failed with %@", error);

  id<TINKAead> twoKeysAead =
      [TINKAeadFactory primitiveWithKeysetHandle:handle error:&error];
  XCTAssertNil(error);

  // Get the AEAD from the kSingleKeyAesGcmKeyset
  NSData *serializedKeysetData = [NSData dataWithBytes:kSingleKeyAesGcmKeyset.data()
                                                length:kSingleKeyAesGcmKeyset.size()];
  reader = [[TINKJSONKeysetReader alloc] initWithSerializedKeyset:serializedKeysetData
                                                            error:&error];

  handle = [[TINKKeysetHandle alloc] initCleartextKeysetHandleWithKeysetReader:reader error:&error];

  id<TINKAead> singleKeyAead = [TINKAeadFactory primitiveWithKeysetHandle:handle error:&error];

  // Encrypt with singleKeyAead, then decrypt with twoKeysAead
  NSData *empty = [[NSData alloc] init];

  NSData *ciphertext = [singleKeyAead encrypt:empty withAdditionalData:empty error:&error];
  XCTAssertNil(error, @"Encrypt failed with %@", error);

  NSData *decryption = [twoKeysAead decrypt:ciphertext withAdditionalData:empty error:&error];
  XCTAssertNil(error, @"Encrypt failed with %@", error);
  XCTAssertEqualObjects(decryption, empty);
}

@end
