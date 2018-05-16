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

#import "objc/TINKKeyTemplate.h"
#import "objc/core/TINKKeyTemplate_Internal.h"

#import <XCTest/XCTest.h>

#include "tink/util/status.h"

@interface TINKKeyTemplateTest : XCTestCase
@end

@implementation TINKKeyTemplateTest

- (void)testInitialization {
  // Verify that the users can't initialize this class directly.
  NSError *error = nil;
  @try {
    TINKKeyTemplate *tpl =
        [[TINKKeyTemplate alloc] initWithKeyTemplate:[[NSObject alloc] init] error:&error];
    XCTAssertNil(tpl);
    XCTAssertNotNil(error);
    XCTAssertEqual(error.code, crypto::tink::util::error::INTERNAL);
    XCTAssertTrue(
        [error.localizedFailureReason containsString:@"Only instantiate from derived classes!"]);
  } @catch (NSException *exception) {
    XCTAssertTrue([exception.reason isEqualToString:@"Only instantiate from derived classes!"]);
  }
}

@end
