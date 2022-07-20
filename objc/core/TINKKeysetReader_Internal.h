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

#ifdef __cplusplus

#import "objc/TINKKeysetReader.h"

#include "tink/keyset_reader.h"

@interface TINKKeysetReader ()

// A reader can only be used once. After that it becomes invalid and shouldn't be used.
// We use this boolean property to mark a reader as used. Any subsequent calls to read will fail.
@property(nonatomic, assign, getter=isUsed) BOOL used;

- (void)setCcReader:(std::unique_ptr<crypto::tink::KeysetReader>)ccReader;
- (std::unique_ptr<crypto::tink::KeysetReader>)ccReader;

@end

#endif  // __cplusplus
