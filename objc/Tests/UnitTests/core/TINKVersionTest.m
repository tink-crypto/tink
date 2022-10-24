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

#import "TINKVersion.h"

#import <XCTest/XCTest.h>

@interface TINKVersionTest : XCTestCase
@end

@implementation TINKVersionTest

- (void)testVersionFormat {
  // The regex represents Semantic Versioning syntax (www.semver.org),
  // i.e. three dot-separated numbers, with an optional suffix
  // that starts with a hyphen, to cover alpha/beta releases and
  // release candiates, for example:
  //   1.2.3
  //   1.2.3-beta
  //   1.2.3-RC1
  NSRegularExpression *expression =
      [[NSRegularExpression alloc] initWithPattern:@"[0-9]+[.][0-9]+[.][0-9]+(-[A-Za-z0-9]+)?"
                                           options:0
                                             error:NULL];
  NSRange range = NSMakeRange(0, [TINKVersion length]);
  NSUInteger numberOfMatches = [expression numberOfMatchesInString:TINKVersion
                                                           options:0
                                                             range:range];
  XCTAssertEqual(numberOfMatches, 1);
}

@end
