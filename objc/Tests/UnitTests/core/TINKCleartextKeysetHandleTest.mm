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

#import <Foundation/Foundation.h>
#import <XCTest/XCTest.h>

#import "objc/TINKBinaryKeysetReader.h"
#import "objc/TINKKeysetHandle+Cleartext.h"
#import "objc/TINKKeysetHandle.h"
#import "objc/core/TINKKeysetHandle_Internal.h"
#import "objc/util/TINKStrings.h"

#include "tink/util/test_keyset_handle.h"
#include "tink/util/test_util.h"
#include "proto/tink.pb.h"

@interface TINKCleartextKeysetHandleTest : XCTestCase
@end

@implementation TINKCleartextKeysetHandleTest

- (void)testReadValidKeyset {
  google::crypto::tink::Keyset keyset;
  google::crypto::tink::Keyset::Key key;
  crypto::tink::test::AddTinkKey("some key type", 42, key,
                                 google::crypto::tink::KeyStatusType::ENABLED,
                                 google::crypto::tink::KeyData::SYMMETRIC, &keyset);
  crypto::tink::test::AddRawKey("some other key type", 711, key,
                                google::crypto::tink::KeyStatusType::ENABLED,
                                google::crypto::tink::KeyData::SYMMETRIC, &keyset);
  keyset.set_primary_key_id(42);

  NSData *serializedKeyset = TINKStringToNSData(keyset.SerializeAsString());

  NSError *error = nil;
  TINKBinaryKeysetReader *reader =
      [[TINKBinaryKeysetReader alloc] initWithSerializedKeyset:serializedKeyset error:&error];

  XCTAssertNil(error);
  XCTAssertNotNil(reader);

  TINKKeysetHandle *handle =
      [[TINKKeysetHandle alloc] initCleartextKeysetHandleWithKeysetReader:reader error:&error];

  XCTAssertNotNil(handle);
  XCTAssertTrue(
      crypto::tink::TestKeysetHandle::GetKeyset(*handle.ccKeysetHandle).SerializeAsString() ==
      keyset.SerializeAsString());

  // Trying to use the same reader again must fail.
  error = nil;
  XCTAssertNil(
      [[TINKKeysetHandle alloc] initCleartextKeysetHandleWithKeysetReader:reader error:&error]);
  XCTAssertNotNil(error);
  XCTAssertEqual((absl::StatusCode)error.code, absl::StatusCode::kResourceExhausted);
  XCTAssertTrue(
      [error.localizedFailureReason containsString:@"A KeysetReader can be used only once."]);
}

- (void)testReadInvalidKeyset {
  NSError *error = nil;
  TINKBinaryKeysetReader *reader = [[TINKBinaryKeysetReader alloc]
      initWithSerializedKeyset:[@"invalid serialized keyset" dataUsingEncoding:NSUTF8StringEncoding]
                         error:&error];

  XCTAssertNil(error);

  TINKKeysetHandle *handle =
      [[TINKKeysetHandle alloc] initCleartextKeysetHandleWithKeysetReader:reader error:&error];

  XCTAssertNil(handle);
  XCTAssertTrue(error.code == crypto::tink::util::error::INVALID_ARGUMENT);
}

- (void)testSerializeKeyset {
  google::crypto::tink::Keyset keyset;
  google::crypto::tink::Keyset::Key key;
  crypto::tink::test::AddTinkKey("some key type", 42, key,
                                 google::crypto::tink::KeyStatusType::ENABLED,
                                 google::crypto::tink::KeyData::SYMMETRIC, &keyset);
  crypto::tink::test::AddRawKey("some other key type", 711, key,
                                google::crypto::tink::KeyStatusType::ENABLED,
                                google::crypto::tink::KeyData::SYMMETRIC, &keyset);
  keyset.set_primary_key_id(42);

  NSData *serializedKeyset = TINKStringToNSData(keyset.SerializeAsString());

  NSError *error = nil;
  TINKBinaryKeysetReader *reader =
      [[TINKBinaryKeysetReader alloc] initWithSerializedKeyset:serializedKeyset error:&error];

  XCTAssertNil(error);
  XCTAssertNotNil(reader);

  TINKKeysetHandle *handle =
      [[TINKKeysetHandle alloc] initCleartextKeysetHandleWithKeysetReader:reader error:&error];

  XCTAssertNotNil(handle);
  XCTAssertTrue([serializedKeyset isEqualToData:handle.serializedKeyset]);
}


@end
