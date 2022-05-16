/**
 * Copyright 2019 Google Inc.
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

#import "objc/TINKDeterministicAeadFactory.h"

#import <XCTest/XCTest.h>

#import "objc/TINKDeterministicAead.h"
#import "objc/TINKDeterministicAeadConfig.h"
#import "objc/TINKDeterministicAeadFactory.h"
#import "objc/TINKKeysetHandle.h"
#import "objc/core/TINKKeysetHandle_Internal.h"
#import "objc/util/TINKStrings.h"

#include "absl/status/status.h"
#include "tink/crypto_format.h"
#include "tink/daead/aes_siv_key_manager.h"
#include "tink/daead/deterministic_aead_config.h"
#include "tink/deterministic_aead.h"
#include "tink/keyset_handle.h"
#include "tink/util/test_keyset_handle.h"
#include "tink/util/status.h"
#include "tink/util/test_util.h"
#include "proto/aes_siv.pb.h"
#include "proto/tink.pb.h"

using crypto::tink::AesSivKeyManager;
using crypto::tink::KeyFactory;
using crypto::tink::TestKeysetHandle;
using crypto::tink::test::AddRawKey;
using crypto::tink::test::AddTinkKey;
using google::crypto::tink::AesSivKey;
using google::crypto::tink::AesSivKeyFormat;
using google::crypto::tink::KeyData;
using google::crypto::tink::Keyset;
using google::crypto::tink::KeyStatusType;

@interface TINKDeterministicAeadFactoryTest : XCTestCase
@end

@implementation TINKDeterministicAeadFactoryTest

- (void)testEmptyKeyset {
  NSError *error = nil;
  TINKDeterministicAeadConfig *aeadConfig =
      [[TINKDeterministicAeadConfig alloc] initWithError:&error];
  XCTAssertNotNil(aeadConfig);
  XCTAssertNil(error);

  Keyset keyset;
  TINKKeysetHandle *handle =
      [[TINKKeysetHandle alloc] initWithCCKeysetHandle:TestKeysetHandle::GetKeysetHandle(keyset)];
  XCTAssertNotNil(handle);

  id<TINKDeterministicAead> aead = [TINKDeterministicAeadFactory primitiveWithKeysetHandle:handle
                                                                                     error:&error];
  XCTAssertNil(aead);
  XCTAssertNotNil(error);
  XCTAssertEqual((absl::StatusCode)error.code, absl::StatusCode::kInvalidArgument);
  XCTAssertTrue([error.localizedFailureReason containsString:@"at least one key"]);
}

- (void)testPrimitive {
  std::string key_type = AesSivKeyManager().get_key_type();

  AesSivKeyFormat key_format;
  key_format.set_key_size(64);

  // Prepare a Keyset.
  Keyset keyset;
  uint32_t key_id_1 = 1234543;
  auto new_key = AesSivKeyManager().CreateKey(key_format).value();
  AddTinkKey(key_type, key_id_1, new_key, KeyStatusType::ENABLED, KeyData::SYMMETRIC, &keyset);

  uint32_t key_id_2 = 726329;
  new_key = AesSivKeyManager().CreateKey(key_format).value();
  AddRawKey(key_type, key_id_2, new_key, KeyStatusType::ENABLED, KeyData::SYMMETRIC, &keyset);

  uint32_t key_id_3 = 7213743;
  new_key = AesSivKeyManager().CreateKey(key_format).value();
  AddTinkKey(key_type, key_id_3, new_key, KeyStatusType::ENABLED, KeyData::SYMMETRIC, &keyset);

  keyset.set_primary_key_id(key_id_3);

  NSError *error = nil;
  TINKDeterministicAeadConfig *aeadConfig =
      [[TINKDeterministicAeadConfig alloc] initWithError:&error];
  XCTAssertNotNil(aeadConfig);
  XCTAssertNil(error);

  TINKKeysetHandle *handle =
      [[TINKKeysetHandle alloc] initWithCCKeysetHandle:TestKeysetHandle::GetKeysetHandle(keyset)];
  XCTAssertNotNil(handle);

  id<TINKDeterministicAead> aead = [TINKDeterministicAeadFactory primitiveWithKeysetHandle:handle
                                                                                     error:&error];
  XCTAssertNotNil(aead);
  XCTAssertNil(error);

  // Test the Aead primitive.
  NSData *plaintext = [@"some_plaintext" dataUsingEncoding:NSUTF8StringEncoding];
  NSData *aad = [@"some_aad" dataUsingEncoding:NSUTF8StringEncoding];
  NSData *ciphertext = [aead encryptDeterministically:plaintext
                                   withAssociatedData:aad
                                                error:&error];
  XCTAssertNil(error);
  XCTAssertNotNil(ciphertext);

  NSData *decrypted = [aead decryptDeterministically:ciphertext
                                  withAssociatedData:aad
                                               error:&error];
  XCTAssertNil(error);
  XCTAssertTrue([plaintext isEqual:decrypted]);

  // Create raw ciphertext with 2nd key, and decrypt with Aead-instance.
  AesSivKey raw_key;
  XCTAssertTrue(raw_key.ParseFromString(keyset.key(1).key_data().value()));
  auto raw_aead =
      std::move(AesSivKeyManager().GetPrimitive<crypto::tink::DeterministicAead>(raw_key).value());
  std::string raw_ciphertext = raw_aead
                                   ->EncryptDeterministically(absl::string_view("some_plaintext"),
                                                              absl::string_view("some_aad"))
                                   .value();
  ciphertext = TINKStringToNSData(raw_ciphertext);

  decrypted = [aead decryptDeterministically:ciphertext withAssociatedData:aad error:&error];
  XCTAssertNil(error);
  XCTAssertTrue([plaintext isEqual:decrypted]);
}

@end
