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

#import "objc/TINKKeysetHandle.h"
#import "objc/core/TINKKeysetHandle_Internal.h"

#import <XCTest/XCTest.h>

#import "objc/TINKAead.h"
#import "objc/TINKAead_Internal.h"
#import "objc/TINKBinaryKeysetReader.h"
#import "objc/util/TINKStrings.h"
#import "proto/Tink.pbobjc.h"

#include "cc/util/test_util.h"
#include "proto/tink.pb.h"

static TINKPBKeyset *gKeyset;

@interface TINKKeysetHandleTest : XCTestCase
@end

@implementation TINKKeysetHandleTest

+ (void)setUp {
  google::crypto::tink::Keyset ccKeyset;
  google::crypto::tink::Keyset::Key ccKey;

  crypto::tink::test::AddTinkKey("some key type", 42, ccKey,
                                 google::crypto::tink::KeyStatusType::ENABLED,
                                 google::crypto::tink::KeyData::SYMMETRIC, &ccKeyset);
  crypto::tink::test::AddRawKey("some other key type", 711, ccKey,
                                google::crypto::tink::KeyStatusType::ENABLED,
                                google::crypto::tink::KeyData::SYMMETRIC, &ccKeyset);
  ccKeyset.set_primary_key_id(42);

  std::string serializedKeyset = ccKeyset.SerializeAsString();

  NSError *error = nil;
  gKeyset = [TINKPBKeyset
      parseFromData:[NSData dataWithBytes:serializedKeyset.data() length:serializedKeyset.length()]
              error:&error];
  XCTAssertNotNil(gKeyset);
  XCTAssertNil(error);
}

- (void)testGoodEncryptedKeyset_Binary {
  crypto::tink::test::DummyAead *ccAead = new crypto::tink::test::DummyAead("dummy aead 42");
  TINKAead *aead = [[TINKAead alloc] initWithPrimitive:ccAead];

  NSData *keysetCiphertext = [aead encrypt:gKeyset.data withAdditionalData:[NSData data] error:nil];

  XCTAssertNotNil(keysetCiphertext);

  TINKPBEncryptedKeyset *encryptedKeyset = [[TINKPBEncryptedKeyset alloc] init];
  encryptedKeyset.encryptedKeyset = keysetCiphertext;

  TINKBinaryKeysetReader *reader =
      [[TINKBinaryKeysetReader alloc] initWithSerializedKeyset:encryptedKeyset.data error:nil];

  TINKKeysetHandle *handle =
      [[TINKKeysetHandle alloc] initWithKeysetReader:reader andKey:aead error:nil];
  XCTAssertNotNil(handle);
  std::string output;
  handle.ccKeysetHandle->get_keyset().SerializeToString(&output);

  XCTAssertTrue(
      [gKeyset.data isEqualToData:[NSData dataWithBytes:output.data() length:output.size()]]);
}

- (void)testWrongAead_Binary {
  crypto::tink::test::DummyAead *ccAead = new crypto::tink::test::DummyAead("dummy aead 42");
  TINKAead *aead = [[TINKAead alloc] initWithPrimitive:ccAead];

  NSData *keysetCiphertext = [aead encrypt:gKeyset.data withAdditionalData:[NSData data] error:nil];

  TINKPBEncryptedKeyset *encryptedKeyset = [[TINKPBEncryptedKeyset alloc] init];
  encryptedKeyset.encryptedKeyset = keysetCiphertext;

  TINKBinaryKeysetReader *reader =
      [[TINKBinaryKeysetReader alloc] initWithSerializedKeyset:encryptedKeyset.data error:nil];

  crypto::tink::test::DummyAead *ccWrongAead = new crypto::tink::test::DummyAead("wrong aead");
  TINKAead *wrongAead = [[TINKAead alloc] initWithPrimitive:ccWrongAead];

  NSError *error = nil;
  TINKKeysetHandle *handle =
      [[TINKKeysetHandle alloc] initWithKeysetReader:reader andKey:wrongAead error:&error];
  XCTAssertNil(handle);
  XCTAssertEqual(error.code, crypto::tink::util::error::INVALID_ARGUMENT);
}

- (void)testNoKeysetInCiphertext_Binary {
  crypto::tink::test::DummyAead *ccAead = new crypto::tink::test::DummyAead("dummy aead 42");
  TINKAead *aead = [[TINKAead alloc] initWithPrimitive:ccAead];
  NSData *keysetCiphertext =
      [aead encrypt:[@"not a serialized keyset" dataUsingEncoding:NSUTF8StringEncoding]
          withAdditionalData:[NSData data]
                       error:nil];

  TINKBinaryKeysetReader *reader =
      [[TINKBinaryKeysetReader alloc] initWithSerializedKeyset:keysetCiphertext error:nil];

  NSError *error = nil;
  TINKKeysetHandle *handle =
      [[TINKKeysetHandle alloc] initWithKeysetReader:reader andKey:aead error:&error];
  XCTAssertNil(handle);
  XCTAssertEqual(error.code, crypto::tink::util::error::INVALID_ARGUMENT);
}

- (void)testWrongCiphertext_Binary {
  crypto::tink::test::DummyAead *ccAead = new crypto::tink::test::DummyAead("dummy aead 42");
  TINKAead *aead = [[TINKAead alloc] initWithPrimitive:ccAead];
  NSString *keysetCiphertext = @"totally wrong ciphertext";

  TINKPBEncryptedKeyset *encryptedKeyset = [[TINKPBEncryptedKeyset alloc] init];
  encryptedKeyset.encryptedKeyset = [keysetCiphertext dataUsingEncoding:NSUTF8StringEncoding];

  TINKBinaryKeysetReader *reader =
      [[TINKBinaryKeysetReader alloc] initWithSerializedKeyset:encryptedKeyset.data error:nil];
  NSError *error = nil;
  TINKKeysetHandle *handle =
      [[TINKKeysetHandle alloc] initWithKeysetReader:reader andKey:aead error:&error];
  XCTAssertNil(handle);
  XCTAssertEqual(error.code, crypto::tink::util::error::INVALID_ARGUMENT);
}

- (void)testInvalidKeyTemplate {
  NSError *error = nil;
  TINKKeysetHandle *handle = [[TINKKeysetHandle alloc] initWithKeyTemplate:nil error:&error];
  XCTAssertNil(handle);
  XCTAssertEqual(error.code, crypto::tink::util::error::INVALID_ARGUMENT);
}

- (void)testValidKeyTeamplte {
  // TODO(candrian): Implement this once the C++ method is working.
}

@end
