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

#import "util/TINKStrings.h"

#include "google/protobuf/util/json_util.h"
#include "tink/util/test_util.h"
#include "proto/tink.pb.h"

static NSData *gBadJSONSerializedKeyset;
static NSData *gGoodJSONSerializedKeyset;
static NSData *gGoodJSONSerializedEncryptedKeyset;
static NSData *gGoodSerializedKeyset;
static NSData *gGoodSerializedEncryptedKeyset;

@interface TINKJSONKeysetReaderTest : XCTestCase
@end

@implementation TINKJSONKeysetReaderTest

+ (void)setUp {
  google::protobuf::util::JsonPrintOptions json_options;
  json_options.add_whitespace = true;
  json_options.always_print_primitive_fields = true;

  google::crypto::tink::Keyset keyset;
  google::crypto::tink::Keyset::Key key;
  crypto::tink::test::AddTinkKey("some key type", 42, key,
                                 google::crypto::tink::KeyStatusType::ENABLED,
                                 google::crypto::tink::KeyData::SYMMETRIC, &keyset);
  crypto::tink::test::AddRawKey("some other key type", 711, key,
                                google::crypto::tink::KeyStatusType::ENABLED,
                                google::crypto::tink::KeyData::SYMMETRIC, &keyset);
  keyset.set_primary_key_id(42);
  std::string ccGoodSerializedKeyset;
  auto status =
      google::protobuf::util::MessageToJsonString(keyset, &ccGoodSerializedKeyset, json_options);
  XCTAssertTrue(status.ok());

  gGoodJSONSerializedKeyset = TINKStringToNSData(ccGoodSerializedKeyset);
  gBadJSONSerializedKeyset = TINKStringToNSData("some weird string");

  google::crypto::tink::EncryptedKeyset encrypted_keyset;
  encrypted_keyset.set_encrypted_keyset("some ciphertext with keyset");

  auto keyset_info = encrypted_keyset.mutable_keyset_info();
  keyset_info->set_primary_key_id(42);
  auto key_info = keyset_info->add_key_info();
  key_info->set_type_url("some type_url");
  key_info->set_key_id(42);
  std::string ccGoodSerializedEncryptedKeyset;
  status = google::protobuf::util::MessageToJsonString(
      encrypted_keyset, &ccGoodSerializedEncryptedKeyset, json_options);
  XCTAssertTrue(status.ok());

  std::string tmp;
  encrypted_keyset.SerializeToString(&tmp);
  gGoodSerializedEncryptedKeyset = TINKStringToNSData(tmp);

  gGoodJSONSerializedEncryptedKeyset = TINKStringToNSData(ccGoodSerializedEncryptedKeyset);
  keyset.SerializeToString(&tmp);
  gGoodSerializedKeyset = TINKStringToNSData(tmp);
}

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wnonnull"
- (void)testReaderCreation {
  // Serialized keyset is nil.
  NSError *error = nil;
  TINKJSONKeysetReader *reader =
      [[TINKJSONKeysetReader alloc] initWithSerializedKeyset:nil error:&error];
  XCTAssertNil(reader);
  XCTAssertNotNil(error);

  // Good serialized keyset.
  error = nil;
  reader = [[TINKJSONKeysetReader alloc] initWithSerializedKeyset:gGoodJSONSerializedKeyset
                                                            error:&error];
  XCTAssertNotNil(reader);
  XCTAssertNil(error);

  // Bad serialized keyset.
  error = nil;
  reader =
      [[TINKJSONKeysetReader alloc] initWithSerializedKeyset:gBadJSONSerializedKeyset error:&error];
  XCTAssertNotNil(reader);
  XCTAssertNil(error);
}
#pragma clang diagnostic pop

@end
