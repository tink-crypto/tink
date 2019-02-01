/**
 * Copyright 2019 Google Inc.
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
@protocol TINKDeterministicAead;

NS_ASSUME_NONNULL_BEGIN;

/**
 * TINKDeterministicAeadFactory allows for obtaining a TINKDeterministicAead primitive from a
 * TINKKeysetHandle.
 *
 * TINKDeterministicAeadFactory gets primitives from the Registry, which can be initialized via
 * convenience methods from TINKDeterministicAeadConfig. Here is an example how one can obtain and
 * use a TINKDeterministicAead primitive:
 *
 * NSError *error = nil;
 * TINKDeterministicAeadConfig *aeadConfig = [[TINKDeterministicAeadConfig alloc]
 *     initWithError:&error];
 * if (!aeadConfig || error) {
 *   // handle error.
 * }
 *
 * if (![TINKConfig registerConfig:aeadConfig error:&error]) {
 *   // handle error.
 * }
 *
 * TINKKeysetHandle keysetHandle = ...;
 * id<TINKDeterministicAead> aead =
 *    [TINKDeterministicAeadFactory primitiveWithKeysetHandle:keysetHandle error:&error];
 * if (!aead || error) {
 *   // handle error.
 * }
 *
 * NSData *plaintext = ...;
 * NSData *additionalData = ...;
 * NSData *ciphertext = [aead encrypt:plaintext withAdditionalData:additionalData error:&error];
 */
@interface TINKDeterministicAeadFactory : NSObject
/**
 * Returns an object that conforms to the TINKDeterministicAead protocol. It uses key material from
 * the keyset specified via @c keysetHandle.
 */
+ (nullable id<TINKDeterministicAead>)primitiveWithKeysetHandle:(TINKKeysetHandle *)keysetHandle
                                                          error:(NSError **)error;
@end

NS_ASSUME_NONNULL_END;
