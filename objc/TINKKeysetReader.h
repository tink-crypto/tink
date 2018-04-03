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

@class TINKPBKeyset;
@class TINKPBEncryptedKeyset;

NS_ASSUME_NONNULL_BEGIN

/**
 * Parent class for keyset readers.
 */
@interface TINKKeysetReader : NSObject

/* Reads a Keyset. Returns nil in case of error and sets error to a descriptive value. */
- (nullable TINKPBKeyset *)readWithError:(NSError **)error;

/* Reads an EncryptedKeyset. Returns nil in case of error and sets error to a descriptive value. */
- (nullable TINKPBEncryptedKeyset *)readEncryptedWithError:(NSError **)error;

@end

NS_ASSUME_NONNULL_END
