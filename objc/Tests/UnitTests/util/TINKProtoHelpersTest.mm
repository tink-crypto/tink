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

#import "objc/util/TINKProtoHelpers.h"

#import <XCTest/XCTest.h>

#import "proto/Tink.pbobjc.h"

#include "proto/tink.pb.h"

@interface TINKProtoHelpersTest : XCTestCase
@end

@implementation TINKProtoHelpersTest

- (void)testConvertKeyTemplateToObjc {
  static NSString *const kTypeURL = @"type.googleapis.com/google.crypto.tink.AesGcmKey";

  NSError *error = nil;

  // Empty KeyTemplate.
  google::crypto::tink::KeyTemplate emptyKeyTemplate;
  TINKPBKeyTemplate *keyTemplate = TINKKeyTemplateToObjc(&emptyKeyTemplate, &error);
  XCTAssertNil(error);
  XCTAssertNotNil(keyTemplate);

  XCTAssertEqual(keyTemplate.typeURL.length, 0);
  XCTAssertEqual(keyTemplate.value.length, 0);
  XCTAssertEqual(keyTemplate.outputPrefixType, TINKPBOutputPrefixType_UnknownPrefix);

  // Prepopulated KeyTemplate.
  google::crypto::tink::KeyTemplate ccKeyTemplate;
  ccKeyTemplate.set_type_url("type.googleapis.com/google.crypto.tink.AesGcmKey");
  ccKeyTemplate.set_value("blah blah");
  ccKeyTemplate.set_output_prefix_type(google::crypto::tink::OutputPrefixType::TINK);

  keyTemplate = TINKKeyTemplateToObjc(&ccKeyTemplate, &error);
  XCTAssertNil(error);
  XCTAssertNotNil(keyTemplate);

  XCTAssertTrue([keyTemplate.typeURL isEqualToString:kTypeURL]);
  XCTAssertTrue(
      [keyTemplate.value isEqualToData:[@"blah blah" dataUsingEncoding:NSUTF8StringEncoding]]);
  XCTAssertEqual((NSInteger)ccKeyTemplate.output_prefix_type(),
                 (NSInteger)keyTemplate.outputPrefixType);
}

@end
