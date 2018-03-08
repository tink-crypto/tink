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

@class TINKKeysetReader;
@class TINKPBKeyTemplate;
@protocol TINKAead;

NS_ASSUME_NONNULL_BEGIN

/**
 * KeysetHandle provides abstracted access to Keysets, to limit the exposure of actual protocol
 * buffers that hold sensitive key material.
 */
@interface TINKKeysetHandle : NSObject

/**
 * Use -initWithKeysetReader:andKey:error: or -initWithTemplate:error: to get an instance of
 * TINKKeysetHandle.
 */
- (nullable instancetype)init NS_UNAVAILABLE;

/**
 * Creates a TINKKeysetHandle from an encrypted keyset obtained via @c reader using @c aeadKey to
 * decrypt the keyset.
 *
 * @param reader  An instance of TINKKeysetReader.
 * @param aeadKey An instance of TINKAead that's used to decrypt the keyset.
 * @param error   If non-nil it will be populated with a descriptive error message.
 * @return        A TINKKeysetHandle, or nil in case of error.
 */
- (nullable instancetype)initWithKeysetReader:(TINKKeysetReader *)reader
                                       andKey:(id<TINKAead>)aeadKey
                                        error:(NSError **)error;

/**
 * Returns a new TINKKeysetHandle that contains a single fresh key generated according to
 * @c keyTemplate.
 *
 * @param keyTemplate A TINKPBKeyTemplate protocol buffer that describes the key to be generated.
 * @param error       If non-nil it will be populated with a descriptive error message.
 * @return            A TINKKeysetHandle, or nil in case of error.
 */
- (nullable instancetype)initWithKeyTemplate:(TINKPBKeyTemplate *)keyTemplate
                                       error:(NSError **)error;

@end

NS_ASSUME_NONNULL_END

