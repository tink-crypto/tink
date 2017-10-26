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

NS_ASSUME_NONNULL_BEGIN

/**
 * KeysetHandle provides abstracted access to Keysets, to limit the exposure of actual protocol
 * buffers that hold sensitive key material.
 */
@interface TINKKeysetHandle : NSObject

@property(nonatomic, readonly) TINKPBKeyset *keyset;

/** Use initWithKeyset: to get an instance of TINKKeysetHandle. */
- (nullable instancetype)init NS_UNAVAILABLE;

/**
 * Designated initializer.
 *
 * @param keyset  An instance of TINKPBKeyset protocol buffer.
 * @return        An instance of TINKKeysetHandle or nil in case of error.
 */
- (nullable instancetype)initWithKeyset:(TINKPBKeyset *)keyset NS_DESIGNATED_INITIALIZER;

@end

NS_ASSUME_NONNULL_END
