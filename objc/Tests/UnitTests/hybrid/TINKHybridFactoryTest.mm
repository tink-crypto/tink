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

#import <XCTest/XCTest.h>

#include <memory>
#include <string>
#include <utility>

#include "absl/strings/escaping.h"

#import "TINKAllConfig.h"
#import "TINKHybridDecrypt.h"
#import "TINKHybridDecryptFactory.h"
#import "TINKHybridEncrypt.h"
#import "TINKHybridEncryptFactory.h"
#import "TINKJSONKeysetReader.h"
#import "TINKKeysetHandle+Cleartext.h"
#import "TINKKeysetHandle.h"

// Generated with Tinkey:
// tinkey create-keyset --key-template ECIES_P256_HKDF_HMAC_SHA256_AES128_GCM --out-format json |\
//   tinkey add-key --key-template ECIES_P256_HKDF_HMAC_SHA256_AES128_GCM --out-format json |\
//   tinkey add-key --key-template ECIES_P256_HKDF_HMAC_SHA256_AES128_GCM --out-format json
// (Plus automatic formatting)
constexpr absl::string_view kMultiKeyEciesKeyset = R"json(
{
  "primaryKeyId": 138849321,
  "key": [
    {
      "keyData": {
        "typeUrl": "type.googleapis.com/google.crypto.tink.EciesAeadHkdfPrivateKey",
        "value": "EosBEkQKBAgCEAMSOhI4CjB0eXBlLmdvb2dsZWFwaXMuY29tL2dvb2dsZS5jcnlwdG8udGluay5BZXNHY21LZXkSAhAQGAEYARohALH+4dcOwY2vRpBvXiOMzFsoL66yAhHB0TBnjgXC2cWQIiB1nh7uDEjA7KSPYrcRxE2uCOPX1MzQZpbS9FIGLzX2PxohAM9yDmyOqaLoFRgavO0mpFh72Wp/7dolb2vlrnMpRXqS",
        "keyMaterialType": "ASYMMETRIC_PRIVATE"
      },
      "status": "ENABLED",
      "keyId": 927487497,
      "outputPrefixType": "TINK"
    },
    {
      "keyData": {
        "typeUrl": "type.googleapis.com/google.crypto.tink.EciesAeadHkdfPrivateKey",
        "value": "EosBEkQKBAgCEAMSOhI4CjB0eXBlLmdvb2dsZWFwaXMuY29tL2dvb2dsZS5jcnlwdG8udGluay5BZXNHY21LZXkSAhAQGAEYARohAJXR8OXxcnr9iW5eY0HfrtvwzctIfs6aVLiYTPAoIRPkIiAgm6A70zykjThWhvnfS0FIQwzGwDnDFiH7Fr+dwrv52hogQcGnSqsab9DiQNUHbO+JyUU6focFdezz/V3YbbVvukw=",
        "keyMaterialType": "ASYMMETRIC_PRIVATE"
      },
      "status": "ENABLED",
      "keyId": 138849321,
      "outputPrefixType": "TINK"
    },
    {
      "keyData": {
        "typeUrl": "type.googleapis.com/google.crypto.tink.EciesAeadHkdfPrivateKey",
        "value": "EooBEkQKBAgCEAMSOhI4CjB0eXBlLmdvb2dsZWFwaXMuY29tL2dvb2dsZS5jcnlwdG8udGluay5BZXNHY21LZXkSAhAQGAEYARogRIQXmow3eAQoc9GJGePefa3jSEpml3yMPM6SFDTqz2oiIG3ApN4jHu/r2jarYac815pSvHi8EHz+AoJgSrM4nfXsGiEAiuxp4DsSH/hx4kPD1sAn3uxDuw9itodcyffPqLaELJ8=",
        "keyMaterialType": "ASYMMETRIC_PRIVATE"
      },
      "status": "ENABLED",
      "keyId": 590961871,
      "outputPrefixType": "TINK"
    }
  ]
}
)json";

// Obtained with tinkey from the above; plus manual editing to split up the keyset.
constexpr absl::string_view kKeyThreePublicKeyset = R"json(
{
  "primaryKeyId": 590961871,
  "key": [
    {
      "keyData": {
        "typeUrl": "type.googleapis.com/google.crypto.tink.EciesAeadHkdfPublicKey",
        "value": "EkQKBAgCEAMSOhI4CjB0eXBlLmdvb2dsZWFwaXMuY29tL2dvb2dsZS5jcnlwdG8udGluay5BZXNHY21LZXkSAhAQGAEYARogRIQXmow3eAQoc9GJGePefa3jSEpml3yMPM6SFDTqz2oiIG3ApN4jHu/r2jarYac815pSvHi8EHz+AoJgSrM4nfXs",
        "keyMaterialType": "ASYMMETRIC_PUBLIC"
      },
      "status": "ENABLED",
      "keyId": 590961871,
      "outputPrefixType": "TINK"
    }
  ]
}
)json";


@interface TINKHybridEncryptDecryptFactoryTest : XCTestCase
@end

@implementation TINKHybridEncryptDecryptFactoryTest

+ (void)setUp {
  NSError *error = nil;
  TINKAllConfig *allConfig = [[TINKAllConfig alloc] initWithError:&error];
  XCTAssertNotNil(allConfig);
  XCTAssertNil(error);
}

- (void)testCreateHybridDecrypt {
  NSData *serializedKeysetData = [NSData dataWithBytes:kMultiKeyEciesKeyset.data()
                                                length:kMultiKeyEciesKeyset.size()];
  NSError *error = nil;
  TINKJSONKeysetReader *reader =
      [[TINKJSONKeysetReader alloc] initWithSerializedKeyset:serializedKeysetData error:&error];
  XCTAssertNil(error, @"TINKJSONKeysetReader creation failed with %@", error);

  TINKKeysetHandle *handle =
      [[TINKKeysetHandle alloc] initCleartextKeysetHandleWithKeysetReader:reader error:&error];
  XCTAssertNil(error, @"TINKKeysetHandle creation failed with %@", error);

  id<TINKHybridDecrypt> hybridDecrypt = [TINKHybridDecryptFactory primitiveWithKeysetHandle:handle
                                                                                      error:&error];
  XCTAssertNotNil(hybridDecrypt);
  XCTAssertNil(error, @"HybridDecrypt creation failed with %@", error);
}

- (void)testCreateHybridEncrypt {
  NSData *serializedKeysetData = [NSData dataWithBytes:kKeyThreePublicKeyset.data()
                                                length:kKeyThreePublicKeyset.size()];
  NSError *error = nil;
  TINKJSONKeysetReader *reader =
      [[TINKJSONKeysetReader alloc] initWithSerializedKeyset:serializedKeysetData error:&error];
  XCTAssertNil(error, @"TINKJSONKeysetReader creation failed with %@", error);

  TINKKeysetHandle *handle =
      [[TINKKeysetHandle alloc] initCleartextKeysetHandleWithKeysetReader:reader error:&error];
  XCTAssertNil(error, @"TINKKeysetHandle creation failed with %@", error);

  id<TINKHybridEncrypt> hybridEncrypt = [TINKHybridEncryptFactory primitiveWithKeysetHandle:handle
                                                                                      error:&error];
  XCTAssertNotNil(hybridEncrypt);
  XCTAssertNil(error, @"HybridEncrypt creation failed with %@", error);
}

- (void)testEncryptThenDecrypt {
  NSData *serializedPrivateKeyData = [NSData dataWithBytes:kMultiKeyEciesKeyset.data()
                                                    length:kMultiKeyEciesKeyset.size()];
  NSError *error = nil;
  TINKJSONKeysetReader *privateReader =
      [[TINKJSONKeysetReader alloc] initWithSerializedKeyset:serializedPrivateKeyData error:&error];
  TINKKeysetHandle *privateHandle =
      [[TINKKeysetHandle alloc] initCleartextKeysetHandleWithKeysetReader:privateReader
                                                                    error:&error];

  id<TINKHybridDecrypt> hybridDecrypt =
      [TINKHybridDecryptFactory primitiveWithKeysetHandle:privateHandle error:&error];

  NSData *serializedPublicKeyData = [NSData dataWithBytes:kKeyThreePublicKeyset.data()
                                                   length:kKeyThreePublicKeyset.size()];
  TINKJSONKeysetReader *publicReader =
      [[TINKJSONKeysetReader alloc] initWithSerializedKeyset:serializedPublicKeyData error:&error];

  TINKKeysetHandle *publicHandle =
      [[TINKKeysetHandle alloc] initCleartextKeysetHandleWithKeysetReader:publicReader
                                                                    error:&error];

  id<TINKHybridEncrypt> hybridEncrypt =
      [TINKHybridEncryptFactory primitiveWithKeysetHandle:publicHandle error:&error];

  NSData* empty = [[NSData alloc] init];
  NSData* ciphertext = [hybridEncrypt encrypt:empty withContextInfo:empty error:&error];
  XCTAssertNil(error, @"encrypt failed with %@", error);

  NSData* decryption = [hybridDecrypt decrypt:ciphertext withContextInfo:empty error:&error];
  XCTAssertNil(error, @"encrypt failed with %@", error);

  XCTAssertEqualObjects(decryption, empty);
}

// We test that changing the context makes decryption fail.
- (void)testEncryptModifyContext_DecryptFails {
  NSData *serializedPrivateKeyData = [NSData dataWithBytes:kMultiKeyEciesKeyset.data()
                                                    length:kMultiKeyEciesKeyset.size()];
  NSError *error = nil;
  TINKJSONKeysetReader *privateReader =
      [[TINKJSONKeysetReader alloc] initWithSerializedKeyset:serializedPrivateKeyData error:&error];
  TINKKeysetHandle *privateHandle =
      [[TINKKeysetHandle alloc] initCleartextKeysetHandleWithKeysetReader:privateReader
                                                                    error:&error];

  id<TINKHybridDecrypt> hybridDecrypt =
      [TINKHybridDecryptFactory primitiveWithKeysetHandle:privateHandle error:&error];

  NSData *serializedPublicKeyData = [NSData dataWithBytes:kKeyThreePublicKeyset.data()
                                                   length:kKeyThreePublicKeyset.size()];
  TINKJSONKeysetReader *publicReader =
      [[TINKJSONKeysetReader alloc] initWithSerializedKeyset:serializedPublicKeyData error:&error];

  TINKKeysetHandle *publicHandle =
      [[TINKKeysetHandle alloc] initCleartextKeysetHandleWithKeysetReader:publicReader
                                                                    error:&error];

  id<TINKHybridEncrypt> hybridEncrypt =
      [TINKHybridEncryptFactory primitiveWithKeysetHandle:publicHandle error:&error];

  NSData* empty = [[NSData alloc] init];
  NSData* ciphertext = [hybridEncrypt encrypt:empty withContextInfo:empty error:&error];
  XCTAssertNil(error, @"encrypt failed with %@", error);

  NSData* wrongContext = [NSData dataWithBytes:"hi" length:2];
  (void)[hybridDecrypt decrypt:ciphertext withContextInfo:wrongContext error:&error];
  XCTAssertNotNil(error);
}

@end
