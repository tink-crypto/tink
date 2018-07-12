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

@class TINKKeysetHandle;
@protocol TINKHybridEncrypt;

NS_ASSUME_NONNULL_BEGIN

/**
 * TINKHybridEncryptFactory allows for obtaining a TINKHybridEncrypt primitive from a
 * TINKKeysetHandle.
 *
 * TINKHybridEncryptFactory gets primitives from the Registry, which can be initialized via
 * convenience methods from TINKHybridConfig. Here is an example how one can obtain and use a
 * TINKHybridEncrypt primitive:
 *
 * NSError *error = nil;
 * TINKHybridConfig *hybridConfig = [[TINKHybridConfig alloc] initWithError:&error];
 * if (!hybridConfig || error) {
 *   // handle error.
 * }
 *
 * if (![TINKConfig registerConfig:hybridConfig error:&error]) {
 *   // handle error.
 * }
 *
 * TINKKeysetHandle keysetHandle = ...;
 * id<TINKHybridEncrypt> hybridEncrypt =
 *    [TINKHybridEncryptFactory primitiveWithKeysetHandle:keysetHandle error:&error];
 * if (!hybridEncrypt || error) {
 *   // handle error.
 * }
 *
 * NSData *plaintext = ...;
 * NSData *contextInfo = ...;
 * NSData *ciphertext = [hybridEncrypt encrypt:plaintext withContextInfo:contextInfo
 *                                                                 error:&error];
 */
@interface TINKHybridEncryptFactory : NSObject

/**
 * Returns an object that conforms to the TINKHybridEncrypt protocol. It uses key material from the
 * keyset specified via @c keysetHandle.
 */
+ (nullable id<TINKHybridEncrypt>)primitiveWithKeysetHandle:(TINKKeysetHandle *)keysetHandle
                                                      error:(NSError **)error;

@end

NS_ASSUME_NONNULL_END
