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
#include "proto/common.pb.h"
#include "proto/tink.pb.h"

#include "absl/status/status.h"
#include "tink/util/status.h"

@interface TINKMacKeyTemplateTest : XCTestCase
@end

static std::string const kHmacKeyTypeURL = "type.googleapis.com/google.crypto.tink.HmacKey";
static std::string const kAesCmacKeyTypeURL = "type.googleapis.com/google.crypto.tink.AesCmacKey";

@implementation TINKMacKeyTemplateTest

- (void)testInvalidKeyTemplate {
  NSError *error = nil;
  // Specify an invalid keyTemplate.
  TINKMacKeyTemplate *keyTemplate =
      [[TINKMacKeyTemplate alloc] initWithKeyTemplate:TINKMacKeyTemplates(-1) error:&error];
  XCTAssertNotNil(error);
  XCTAssertNil(keyTemplate);
  XCTAssertEqual((absl::StatusCode)error.code, absl::StatusCode::kInvalidArgument);
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

  XCTAssertTrue(keyTemplate.ccKeyTemplate->type_url() == kHmacKeyTypeURL);
  XCTAssertTrue(keyTemplate.ccKeyTemplate->output_prefix_type() ==
                google::crypto::tink::OutputPrefixType::TINK);
}

- (void)testHmac256BittagSha256 {
  // Get a HmacSha256 key template.
  NSError *error = nil;
  TINKMacKeyTemplate *keyTemplate =
      [[TINKMacKeyTemplate alloc] initWithKeyTemplate:TINKHmacSha256 error:&error];
  XCTAssertNil(error);
  XCTAssertNotNil(keyTemplate);

  XCTAssertTrue(keyTemplate.ccKeyTemplate->type_url() == kHmacKeyTypeURL);
  XCTAssertTrue(keyTemplate.ccKeyTemplate->output_prefix_type() ==
                google::crypto::tink::OutputPrefixType::TINK);
}

- (void)testHmac256BittagSha512 {
  // Get a HmacSha512HalfSizeTag key template.
  NSError *error = nil;
  TINKMacKeyTemplate *keyTemplate =
      [[TINKMacKeyTemplate alloc] initWithKeyTemplate:TINKHmacSha512HalfSizeTag error:&error];
  XCTAssertNil(error);
  XCTAssertNotNil(keyTemplate);

  XCTAssertTrue(keyTemplate.ccKeyTemplate->type_url() == kHmacKeyTypeURL);
  XCTAssertTrue(keyTemplate.ccKeyTemplate->output_prefix_type() ==
                google::crypto::tink::OutputPrefixType::TINK);
}

- (void)testHmac512BittagSha512 {
  // Get a HmacSha512 key template.
  NSError *error = nil;
  TINKMacKeyTemplate *keyTemplate =
      [[TINKMacKeyTemplate alloc] initWithKeyTemplate:TINKHmacSha512 error:&error];
  XCTAssertNil(error);
  XCTAssertNotNil(keyTemplate);

  XCTAssertTrue(keyTemplate.ccKeyTemplate->type_url() == kHmacKeyTypeURL);
  XCTAssertTrue(keyTemplate.ccKeyTemplate->output_prefix_type() ==
                google::crypto::tink::OutputPrefixType::TINK);
}

- (void)testAesCmac {
  // Get an AesCmac key template.
  NSError *error = nil;
  TINKMacKeyTemplate *keyTemplate =
      [[TINKMacKeyTemplate alloc] initWithKeyTemplate:TINKAesCmac error:&error];
  XCTAssertNil(error);
  XCTAssertNotNil(keyTemplate);

  XCTAssertTrue(keyTemplate.ccKeyTemplate->type_url() == kAesCmacKeyTypeURL);
  XCTAssertTrue(keyTemplate.ccKeyTemplate->output_prefix_type() ==
                google::crypto::tink::OutputPrefixType::TINK);
}

@end
