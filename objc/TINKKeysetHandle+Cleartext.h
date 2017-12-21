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

#import "objc/TINKKeysetHandle.h"
#import "objc/TINKKeysetReader.h"

NS_ASSUME_NONNULL_BEGIN

/**
 * A category that
 * Creates keyset handles from cleartext keysets. This API allows loading cleartext keysets, thus
 * its usage should be restricted.
 */
@interface TINKKeysetHandle (Cleartext)

/**
 * Creates a TINKKeysetHandle with a cleartext keyset obtained via @c reader.
 *
 * @param reader The reader that will read the cleartext keyset.
 * @param error  If non-nil it will be populated with a descriptive error when the operation fails.
 * @return       A TINKKeysetHandle, or nil in case of error.
 */
- (nullable instancetype)initCleartextKeysetHandleWithKeysetReader:(TINKKeysetReader *)reader
                                                             error:(NSError **)error;

@end

NS_ASSUME_NONNULL_END
