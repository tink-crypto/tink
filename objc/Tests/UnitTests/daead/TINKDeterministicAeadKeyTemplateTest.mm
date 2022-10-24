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

#import "TINKDeterministicAeadKeyTemplate.h"

#import <XCTest/XCTest.h>

#import "TINKKeyTemplate.h"
#import "core/TINKKeyTemplate_Internal.h"
#include "proto/common.pb.h"
#include "proto/tink.pb.h"

@interface TINKDeterministicAeadKeyTemplatesTest : XCTestCase
@end

@implementation TINKDeterministicAeadKeyTemplatesTest

- (void)testAesSivKeyTemplates {
  static std::string const kTypeURL = "type.googleapis.com/google.crypto.tink.AesSivKey";

  NSError *error = nil;
  // AES-256 SIV
  TINKDeterministicAeadKeyTemplate *tpl =
      [[TINKDeterministicAeadKeyTemplate alloc] initWithKeyTemplate:TINKAes256Siv error:&error];
  XCTAssertNil(error);
  XCTAssertNotNil(tpl);

  XCTAssertTrue(tpl.ccKeyTemplate->type_url() == kTypeURL);
  XCTAssertTrue(tpl.ccKeyTemplate->output_prefix_type() ==
                google::crypto::tink::OutputPrefixType::TINK);
}

@end
