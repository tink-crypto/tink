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
@protocol TINKMac;

NS_ASSUME_NONNULL_BEGIN

/**
 * TINKMacFactory allows for obtaining a TINKMac primitive from a TINKKeysetHandle.
 *
 * TINKMacFactory gets primitives from the Registry, which can be initialized via convenience
 * methods in TINKMacConfig. Here is an example how one can obtain and use a TINKMac primitive:
 *
 * NSError *error = nil;
 * TINKMacConfig *macConfig = [[TINKMacConfig alloc] initWithError:&error];
 * if (!macConfig || error) {
 *   // handle error.
 * }
 *
 * if (![TINKConfig registerConfig:macConfig error:&error]) {
 *   // handle error.
 * }
 *
 * TINKKeysetHandle keysetHandle = ...;
 * id<TINKMac> mac = [TINKMacFactory primitiveWithKeysetHandle:keysetHandle error:&error];
 * if (!mac || error) {
 *   // handle error.
 * }
 *
 */
@interface TINKMacFactory : NSObject

/**
 * Returns an object that conforms to the TINKMac protocol. It uses key material from the keyset
 * specified via @c keysetHandle.
 */
+ (nullable id<TINKMac>)primitiveWithKeysetHandle:(TINKKeysetHandle *)keysetHandle
                                            error:(NSError **)error;

@end

NS_ASSUME_NONNULL_END
