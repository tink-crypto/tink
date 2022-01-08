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

#import "objc/TINKAeadFactory.h"

#import <XCTest/XCTest.h>

#import "objc/TINKAead.h"
#import "objc/TINKAeadConfig.h"
#import "objc/TINKAeadFactory.h"
#import "objc/TINKKeysetHandle.h"
#import "objc/core/TINKKeysetHandle_Internal.h"
#import "objc/util/TINKStrings.h"

#include "absl/status/status.h"
#include "tink/aead.h"
#include "tink/aead/aead_config.h"
#include "tink/aead/aes_gcm_key_manager.h"
#include "tink/crypto_format.h"
#include "tink/keyset_handle.h"
#include "tink/util/status.h"
#include "tink/util/test_keyset_handle.h"
#include "tink/util/test_util.h"
#include "proto/aes_gcm.pb.h"
#include "proto/tink.pb.h"

using crypto::tink::AesGcmKeyManager;
using crypto::tink::KeyFactory;
using crypto::tink::TestKeysetHandle;
using crypto::tink::test::AddRawKey;
using crypto::tink::test::AddTinkKey;
using google::crypto::tink::AesGcmKey;
using google::crypto::tink::AesGcmKeyFormat;
using google::crypto::tink::KeyData;
using google::crypto::tink::Keyset;
using google::crypto::tink::KeyStatusType;

@interface TINKAeadFactoryTest : XCTestCase
@end

@implementation TINKAeadFactoryTest

- (void)testEmptyKeyset {
  NSError *error = nil;
  TINKAeadConfig *aeadConfig = [[TINKAeadConfig alloc] initWithError:&error];
  XCTAssertNotNil(aeadConfig);
  XCTAssertNil(error);

  Keyset keyset;
  TINKKeysetHandle *handle =
      [[TINKKeysetHandle alloc] initWithCCKeysetHandle:TestKeysetHandle::GetKeysetHandle(keyset)];
  XCTAssertNotNil(handle);

  error = nil;
  id<TINKAead> aead = [TINKAeadFactory primitiveWithKeysetHandle:handle error:&error];
  XCTAssertNil(aead);
  XCTAssertNotNil(error);
  XCTAssertEqual((absl::StatusCode)error.code, absl::StatusCode::kInvalidArgument);
  XCTAssertTrue([error.localizedFailureReason containsString:@"at least one key"]);
}

- (void)testPrimitive {
  // Prepare a template for generating keys for a Keyset.
  std::string key_type = AesGcmKeyManager().get_key_type();

  AesGcmKeyFormat key_format;
  key_format.set_key_size(16);

  // Prepare a Keyset.
  Keyset keyset;
  uint32_t key_id_1 = 1234543;
  AesGcmKey new_key = AesGcmKeyManager().CreateKey(key_format).ValueOrDie();
  AddTinkKey(key_type, key_id_1, new_key, KeyStatusType::ENABLED, KeyData::SYMMETRIC, &keyset);

  uint32_t key_id_2 = 726329;
  new_key = AesGcmKeyManager().CreateKey(key_format).ValueOrDie();
  AddRawKey(key_type, key_id_2, new_key, KeyStatusType::ENABLED, KeyData::SYMMETRIC, &keyset);

  uint32_t key_id_3 = 7213743;
  new_key = AesGcmKeyManager().CreateKey(key_format).ValueOrDie();
  AddTinkKey(key_type, key_id_3, new_key, KeyStatusType::ENABLED, KeyData::SYMMETRIC, &keyset);

  keyset.set_primary_key_id(key_id_3);

  NSError *error = nil;
  TINKAeadConfig *aeadConfig = [[TINKAeadConfig alloc] initWithError:&error];
  XCTAssertNotNil(aeadConfig);
  XCTAssertNil(error);

  TINKKeysetHandle *handle =
      [[TINKKeysetHandle alloc] initWithCCKeysetHandle:TestKeysetHandle::GetKeysetHandle(keyset)];
  XCTAssertNotNil(handle);

  id<TINKAead> aead = [TINKAeadFactory primitiveWithKeysetHandle:handle error:&error];
  XCTAssertNotNil(aead);
  XCTAssertNil(error);

  // Test the Aead primitive.
  NSData *plaintext = [@"some_plaintext" dataUsingEncoding:NSUTF8StringEncoding];
  NSData *aad = [@"some_aad" dataUsingEncoding:NSUTF8StringEncoding];
  NSData *ciphertext = [aead encrypt:plaintext withAdditionalData:aad error:&error];
  XCTAssertNil(error);
  XCTAssertNotNil(ciphertext);

  NSData *decrypted = [aead decrypt:ciphertext withAdditionalData:aad error:&error];
  XCTAssertNil(error);
  XCTAssertTrue([plaintext isEqual:decrypted]);

  // Create raw ciphertext with 2nd key, and decrypt with Aead-instance.
  AesGcmKey raw_key;
  XCTAssertTrue(raw_key.ParseFromString(keyset.key(1).key_data().value()));
  auto raw_aead =
      std::move(AesGcmKeyManager().GetPrimitive<crypto::tink::Aead>(raw_key).ValueOrDie());
  std::string raw_ciphertext =
      raw_aead->Encrypt(absl::string_view("some_plaintext"), absl::string_view("some_aad"))
          .ValueOrDie();
  ciphertext = TINKStringToNSData(raw_ciphertext);

  decrypted = [aead decrypt:ciphertext withAdditionalData:aad error:&error];
  XCTAssertNil(error);
  XCTAssertTrue([plaintext isEqual:decrypted]);
}

@end

