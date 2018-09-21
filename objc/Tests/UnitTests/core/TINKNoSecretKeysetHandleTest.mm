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
#import "objc/TINKKeysetHandle+NoSecret.h"
#import "objc/TINKKeysetHandle.h"
#import "objc/core/TINKKeysetHandle_Internal.h"
#import "objc/util/TINKStrings.h"

#include "absl/memory/memory.h"
#include "tink/util/keyset_util.h"
#include "tink/util/test_util.h"
#include "proto/tink.pb.h"

using ::crypto::tink::test::AddRawKey;
using ::crypto::tink::test::AddTinkKey;
using ::google::crypto::tink::KeyData;
using ::google::crypto::tink::Keyset;
using ::google::crypto::tink::KeyStatusType;

@interface TINKNoSecretKeysetHandleTest : XCTestCase
@end

@implementation TINKNoSecretKeysetHandleTest

- (void)testRead {
  auto keyset = absl::make_unique<Keyset>();
  Keyset::Key key;
  AddTinkKey("some key type", 42, key, KeyStatusType::ENABLED, KeyData::ASYMMETRIC_PUBLIC,
             keyset.get());
  AddRawKey("some other key type", 711, key, KeyStatusType::ENABLED, KeyData::REMOTE, keyset.get());
  keyset->set_primary_key_id(42);

  NSData *serializedKeyset = TINKStringToNSData(keyset->SerializeAsString());

  NSError *error = nil;
  TINKBinaryKeysetReader *reader =
      [[TINKBinaryKeysetReader alloc] initWithSerializedKeyset:serializedKeyset error:&error];

  XCTAssertNil(error);
  XCTAssertNotNil(reader);

  TINKKeysetHandle *handle =
      [[TINKKeysetHandle alloc] initNoSecretKeysetHandleWithKeysetReader:reader error:&error];

  XCTAssertNotNil(handle);
  XCTAssertTrue(crypto::tink::KeysetUtil::GetKeyset(*handle.ccKeysetHandle).SerializeAsString() ==
                keyset->SerializeAsString());
}

- (void)testFailForTypeUnknown {
  auto keyset = absl::make_unique<Keyset>();
  Keyset::Key key;
  AddTinkKey("some key type", 42, key, KeyStatusType::ENABLED, KeyData::UNKNOWN_KEYMATERIAL,
             keyset.get());
  keyset->set_primary_key_id(42);

  NSData *serializedKeyset = TINKStringToNSData(keyset->SerializeAsString());

  NSError *error = nil;
  TINKBinaryKeysetReader *reader =
      [[TINKBinaryKeysetReader alloc] initWithSerializedKeyset:serializedKeyset error:&error];

  XCTAssertNil(error);
  XCTAssertNotNil(reader);

  TINKKeysetHandle *handle =
      [[TINKKeysetHandle alloc] initNoSecretKeysetHandleWithKeysetReader:reader error:&error];

  XCTAssertNil(handle);
  XCTAssertEqual(error.code, crypto::tink::util::error::FAILED_PRECONDITION);
  XCTAssertTrue([error.localizedFailureReason
      containsString:@"Cannot create KeysetHandle with secret key material"]);
}

- (void)testFailForTypeSymmetric {
  auto keyset = absl::make_unique<Keyset>();
  Keyset::Key key;
  AddTinkKey("some key type", 42, key, KeyStatusType::ENABLED, KeyData::SYMMETRIC, keyset.get());
  keyset->set_primary_key_id(42);

  NSData *serializedKeyset = TINKStringToNSData(keyset->SerializeAsString());

  NSError *error = nil;
  TINKBinaryKeysetReader *reader =
      [[TINKBinaryKeysetReader alloc] initWithSerializedKeyset:serializedKeyset error:&error];

  XCTAssertNil(error);
  XCTAssertNotNil(reader);

  TINKKeysetHandle *handle =
      [[TINKKeysetHandle alloc] initNoSecretKeysetHandleWithKeysetReader:reader error:&error];

  XCTAssertNil(handle);
  XCTAssertEqual(error.code, crypto::tink::util::error::FAILED_PRECONDITION);
  XCTAssertTrue([error.localizedFailureReason
      containsString:@"Cannot create KeysetHandle with secret key material"]);
}

- (void)testFailForTypeAssymmetricPrivate {
  auto keyset = absl::make_unique<Keyset>();
  Keyset::Key key;
  AddTinkKey("some key type", 42, key, KeyStatusType::ENABLED, KeyData::ASYMMETRIC_PRIVATE,
             keyset.get());
  keyset->set_primary_key_id(42);

  NSData *serializedKeyset = TINKStringToNSData(keyset->SerializeAsString());

  NSError *error = nil;
  TINKBinaryKeysetReader *reader =
      [[TINKBinaryKeysetReader alloc] initWithSerializedKeyset:serializedKeyset error:&error];

  XCTAssertNil(error);
  XCTAssertNotNil(reader);

  TINKKeysetHandle *handle =
      [[TINKKeysetHandle alloc] initNoSecretKeysetHandleWithKeysetReader:reader error:&error];

  XCTAssertNil(handle);
  XCTAssertEqual(error.code, crypto::tink::util::error::FAILED_PRECONDITION);
  XCTAssertTrue([error.localizedFailureReason
      containsString:@"Cannot create KeysetHandle with secret key material"]);
}

- (void)testFailForHidden {
  auto keyset = absl::make_unique<Keyset>();
  Keyset::Key key;
  AddTinkKey("some key type", 42, key, KeyStatusType::ENABLED, KeyData::ASYMMETRIC_PUBLIC,
             keyset.get());
  for (int i = 0; i < 10; ++i) {
    AddTinkKey(absl::StrCat("more key type", i), i, key, KeyStatusType::ENABLED,
               KeyData::ASYMMETRIC_PUBLIC, keyset.get());
  }
  AddRawKey("some other key type", 10, key, KeyStatusType::ENABLED, KeyData::ASYMMETRIC_PRIVATE,
            keyset.get());
  for (int i = 0; i < 10; ++i) {
    AddRawKey(absl::StrCat("more key type", i + 100), i + 100, key, KeyStatusType::ENABLED,
              KeyData::ASYMMETRIC_PUBLIC, keyset.get());
  }
  keyset->set_primary_key_id(42);

  NSData *serializedKeyset = TINKStringToNSData(keyset->SerializeAsString());

  NSError *error = nil;
  TINKBinaryKeysetReader *reader =
      [[TINKBinaryKeysetReader alloc] initWithSerializedKeyset:serializedKeyset error:&error];

  XCTAssertNil(error);
  XCTAssertNotNil(reader);

  TINKKeysetHandle *handle =
      [[TINKKeysetHandle alloc] initNoSecretKeysetHandleWithKeysetReader:reader error:&error];

  XCTAssertNil(handle);
  XCTAssertEqual(error.code, crypto::tink::util::error::FAILED_PRECONDITION);
  XCTAssertTrue([error.localizedFailureReason
      containsString:@"Cannot create KeysetHandle with secret key material"]);
}

@end
