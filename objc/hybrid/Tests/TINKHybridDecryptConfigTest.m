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

#import "objc/hybrid/TINKHybridDecryptConfig.h"

#import <XCTest/XCTest.h>

#import "objc/hybrid/TINKEciesAeadHkdfPrivateKeyManager.h"

@interface TINKHybridDecryptConfigTest : XCTestCase
@end

@implementation TINKHybridDecryptConfigTest

// Disabled because we need a way to reset the registry if we want to test this
// along with registerStandardKeyTypes.
#if 0
- (void)testRegisterCustomKeyManager {
  NSError *error = nil;

  TINKEciesAeadHkdfPrivateKeyManager *keyManager =
      [[TINKEciesAeadHkdfPrivateKeyManager alloc] init];
  XCTAssertNotNil(keyManager);

  // Registering the custom key manager for the first time must succeed.
  XCTAssertTrue([TINKHybridDecryptConfig registerKeyManager:keyManager error:&error]);
  XCTAssertNil(error);

  // Registering again should fail with already-exists error.
  XCTAssertFalse([TINKHybridDecryptConfig registerKeyManager:keyManager error:&error]);
}
#endif

- (void)testRegisterStandardKeyTypes {
  XCTAssertTrue([TINKHybridDecryptConfig registerStandardKeyTypes]);

  // Calling it a second time must not fail.
  XCTAssertTrue([TINKHybridDecryptConfig registerStandardKeyTypes]);
}

@end
