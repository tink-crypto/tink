/**
 * Copyright 2018 Google Inc.
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

#import "objc/TINKMacKeyTemplate.h"

#import <XCTest/XCTest.h>

#import "objc/TINKKeyTemplate.h"
#import "objc/core/TINKKeyTemplate_Internal.h"
#import "objc/util/TINKProtoHelpers.h"
#import "proto/Common.pbobjc.h"
#import "proto/Hmac.pbobjc.h"
#import "proto/Tink.pbobjc.h"

#include "tink/util/status.h"

@interface TINKMacKeyTemplateTest : XCTestCase
@end

static NSString *const kTypeURL = @"type.googleapis.com/google.crypto.tink.HmacKey";

@implementation TINKMacKeyTemplateTest

- (void)testInvalidKeyTemplate {
  NSError *error = nil;
  // Specify an invalid keyTemplate.
  TINKMacKeyTemplate *keyTemplate =
      [[TINKMacKeyTemplate alloc] initWithKeyTemplate:TINKMacKeyTemplates(-1) error:&error];
  XCTAssertNotNil(error);
  XCTAssertNil(keyTemplate);
  XCTAssertEqual(error.code, crypto::tink::util::error::INVALID_ARGUMENT);
  NSDictionary *userInfo = [error userInfo];
  NSString *errorString = [userInfo objectForKey:NSLocalizedFailureReasonErrorKey];
  XCTAssertTrue([errorString containsString:@"Invalid TINKMacKeyTemplate"]);
}

- (void)testHmac128BittagSha256 {
  // Get a HmacSha256HalfSizeTag key template.
  NSError *error = nil;
  TINKMacKeyTemplate *keyTemplate =
      [[TINKMacKeyTemplate alloc] initWithKeyTemplate:TINKHmacSha256HalfSizeTag error:&error];
  XCTAssertNil(error);
  XCTAssertNotNil(keyTemplate);

  TINKPBKeyTemplate *objcKeyTemplate = TINKKeyTemplateToObjc(keyTemplate.ccKeyTemplate, &error);
  XCTAssertNil(error);
  XCTAssertNotNil(objcKeyTemplate);

  XCTAssertTrue([kTypeURL isEqualToString:objcKeyTemplate.typeURL]);
  XCTAssertEqual(objcKeyTemplate.outputPrefixType, TINKPBOutputPrefixType_Tink);
  error = nil;
  TINKPBHmacKeyFormat *keyFormat =
      [TINKPBHmacKeyFormat parseFromData:objcKeyTemplate.value error:&error];
  XCTAssertNil(error);
  XCTAssertNotNil(keyFormat);

  XCTAssertEqual(keyFormat.keySize, 32);
  XCTAssertEqual(keyFormat.params.tagSize, 16);
  XCTAssertEqual(keyFormat.params.hash_p, TINKPBHashType_Sha256);
}

- (void)testHmac256BittagSha256 {
  // Get a HmacSha256 key template.
  NSError *error = nil;
  TINKMacKeyTemplate *keyTemplate =
      [[TINKMacKeyTemplate alloc] initWithKeyTemplate:TINKHmacSha256 error:&error];
  XCTAssertNil(error);
  XCTAssertNotNil(keyTemplate);

  TINKPBKeyTemplate *objcKeyTemplate = TINKKeyTemplateToObjc(keyTemplate.ccKeyTemplate, &error);
  XCTAssertNil(error);
  XCTAssertNotNil(objcKeyTemplate);

  XCTAssertTrue([kTypeURL isEqualToString:objcKeyTemplate.typeURL]);
  XCTAssertEqual(objcKeyTemplate.outputPrefixType, TINKPBOutputPrefixType_Tink);
  error = nil;
  TINKPBHmacKeyFormat *keyFormat =
      [TINKPBHmacKeyFormat parseFromData:objcKeyTemplate.value error:&error];
  XCTAssertNil(error);
  XCTAssertNotNil(keyFormat);

  XCTAssertEqual(keyFormat.keySize, 32);
  XCTAssertEqual(keyFormat.params.tagSize, 32);
  XCTAssertEqual(keyFormat.params.hash_p, TINKPBHashType_Sha256);
}

@end
