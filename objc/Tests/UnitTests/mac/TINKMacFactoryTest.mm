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

#import "objc/TINKKeysetHandle.h"
#import "objc/TINKMac.h"
#import "objc/TINKMacConfig.h"
#import "objc/TINKMacFactory.h"
#import "objc/core/TINKKeysetHandle_Internal.h"
#import "objc/util/TINKStrings.h"

#include "absl/status/status.h"
#include "tink/crypto_format.h"
#include "tink/keyset_handle.h"
#include "tink/mac.h"
#include "tink/mac/hmac_key_manager.h"
#include "tink/mac/mac_config.h"
#include "tink/util/status.h"
#include "tink/util/test_keyset_handle.h"
#include "tink/util/test_util.h"
#include "proto/hmac.pb.h"
#include "proto/tink.pb.h"

using crypto::tink::HmacKeyManager;
using crypto::tink::KeyFactory;
using crypto::tink::TestKeysetHandle;
using crypto::tink::test::AddRawKey;
using crypto::tink::test::AddTinkKey;
using google::crypto::tink::HashType;
using google::crypto::tink::HmacKey;
using google::crypto::tink::HmacKeyFormat;
using google::crypto::tink::KeyData;
using google::crypto::tink::Keyset;
using google::crypto::tink::KeyStatusType;

@interface TINKMacFactoryTest : XCTestCase
@end

@implementation TINKMacFactoryTest

- (void)testEmptyKeyset {
  Keyset keyset;
  TINKKeysetHandle *handle =
      [[TINKKeysetHandle alloc] initWithCCKeysetHandle:TestKeysetHandle::GetKeysetHandle(keyset)];
  XCTAssertNotNil(handle);

  NSError *error = nil;
  id<TINKMac> mac = [TINKMacFactory primitiveWithKeysetHandle:handle error:&error];
  XCTAssertNil(mac);
  XCTAssertNotNil(error);
  XCTAssertEqual((absl::StatusCode)error.code, absl::StatusCode::kInvalidArgument);
  XCTAssertTrue([error.localizedFailureReason containsString:@"at least one key"]);
}

- (void)testPrimitive {
  // Prepare a template for generating keys for a Keyset.
  std::string key_type = HmacKeyManager().get_key_type();
  HmacKeyManager key_manager;

  HmacKeyFormat key_format;
  key_format.set_key_size(16);
  key_format.mutable_params()->set_tag_size(10);
  key_format.mutable_params()->set_hash(HashType::SHA256);

  // Prepare a Keyset.
  Keyset keyset;
  uint32_t key_id_1 = 1234543;
  HmacKey new_key = HmacKeyManager().CreateKey(key_format).value();
  AddTinkKey(key_type, key_id_1, new_key, KeyStatusType::ENABLED, KeyData::SYMMETRIC, &keyset);

  uint32_t key_id_2 = 726329;
  new_key = HmacKeyManager().CreateKey(key_format).value();
  AddRawKey(key_type, key_id_2, new_key, KeyStatusType::ENABLED, KeyData::SYMMETRIC, &keyset);

  uint32_t key_id_3 = 7213743;
  new_key = HmacKeyManager().CreateKey(key_format).value();
  AddTinkKey(key_type, key_id_3, new_key, KeyStatusType::ENABLED, KeyData::SYMMETRIC, &keyset);

  keyset.set_primary_key_id(key_id_3);

  NSError *error = nil;
  TINKMacConfig *macConfig = [[TINKMacConfig alloc] initWithError:&error];
  XCTAssertNotNil(macConfig);
  XCTAssertNil(error);

  TINKKeysetHandle *handle =
      [[TINKKeysetHandle alloc] initWithCCKeysetHandle:TestKeysetHandle::GetKeysetHandle(keyset)];
  XCTAssertNotNil(handle);

  id<TINKMac> mac = [TINKMacFactory primitiveWithKeysetHandle:handle error:&error];
  XCTAssertNotNil(mac);
  XCTAssertNil(error);

  // Compute the mac.
  NSData *data = [@"some_data_for_mac" dataUsingEncoding:NSUTF8StringEncoding];
  error = nil;
  NSData *computedMac = [mac computeMacForData:data error:&error];
  XCTAssertNil(error);
  XCTAssertNotNil(computedMac);

  // Verify that the mac is correct.
  XCTAssertTrue([mac verifyMac:computedMac forData:data error:&error]);
  XCTAssertNil(error);

  // Try again with different data.
  XCTAssertFalse([mac verifyMac:computedMac
                        forData:[@"bad data for mac" dataUsingEncoding:NSUTF8StringEncoding]
                          error:&error]);
  XCTAssertEqual((absl::StatusCode)error.code, absl::StatusCode::kInvalidArgument);
  XCTAssertTrue([error.localizedFailureReason containsString:@"verification failed"]);

  // One more time with the wrong mac.
  XCTAssertFalse([mac verifyMac:[@"some bad mac value" dataUsingEncoding:NSUTF8StringEncoding]
                        forData:data
                          error:&error]);
  XCTAssertEqual((absl::StatusCode)error.code, absl::StatusCode::kInvalidArgument);
  XCTAssertTrue([error.localizedFailureReason containsString:@"verification failed"]);

  const char *dataBytes = (const char *)data.bytes;
  XCTAssertTrue(dataBytes != NULL);

  // Flip all the bits in data one by one.
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

      XCTAssertFalse(
          [mac verifyMac:computedMac forData:[NSData dataWithData:mutableData] error:&error]);
      XCTAssertEqual((absl::StatusCode)error.code, absl::StatusCode::kInvalidArgument);
      XCTAssertTrue([error.localizedFailureReason containsString:@"verification failed"]);
    }
  }

  const char *macBytes = (const char *)computedMac.bytes;
  XCTAssertTrue(macBytes != NULL);

  // Flip all the bits in the MAC one by one.
  for (NSUInteger byteIndex = 0; byteIndex < computedMac.length; byteIndex++) {
    const char currentByte = macBytes[byteIndex];

    for (NSUInteger bitIndex = 0; bitIndex < 8; bitIndex++) {
      // Flip every bit on this byte.
      char flippedByte = (currentByte ^ (1 << bitIndex));
      XCTAssertTrue(flippedByte != currentByte);

      // Replace the mutated byte in the original data.
      NSMutableData *mutableMac = computedMac.mutableCopy;
      char *mutableBytes = (char *)mutableMac.mutableBytes;
      mutableBytes[byteIndex] = flippedByte;

      XCTAssertFalse([mac verifyMac:[NSData dataWithData:mutableMac] forData:data error:&error]);
      XCTAssertEqual((absl::StatusCode)error.code, absl::StatusCode::kInvalidArgument);
      XCTAssertTrue([error.localizedFailureReason containsString:@"verification failed"]);
    }
  }
}

@end
