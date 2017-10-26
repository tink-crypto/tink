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
@class TINKMacKeyManager;
@protocol TINKKeyManager;
@protocol TINKMac;

NS_ASSUME_NONNULL_BEGIN

/**
 * TINKMacFactory allows for obtaining a TINKMac primitive from a TINKKeysetHandle.
 *
 * TINKMacFactory gets primitives from the Registry, which can be initialized via convenience
 * methods in TINKMacConfig. Here is an example how one can obtain and use a TINKMac primitive:
 *
 *   [TINKMacConfig registerStandardKeyTypes];
 *   TINKKeysetHandle *keysetHandle = [TINKKeysetHandle initWithKeyset:...];
 *
 *   NSError *error = nil;
 *   id <TINKMac> mac = [TINKMacFactory primitiveWithKeysetHanlde:keysetHandle error:&error];
 *   if (error) {
 *     // handle error
 *   }
 *
 *   NSData *data = ...;
 *   NSData *macValue = [mac computeMacForData:data error:&error];
 *   if (error) {
 *     // handle error
 *   }
 */
@interface TINKMacFactory : NSObject

/**
 * Returns a TINKMac-primitive that uses key material from the keyset specified via @c keysetHandle.
 */
+ (nullable id<TINKMac>)primitiveWithKeysetHandle:(TINKKeysetHandle *)keysetHandle
                                            error:(NSError **)error;

/**
 * Returns a TINKMac-primitive that uses key material from the keyset specified via @c keysetHandle
 * and is instantiated by the given @c keyManager (instead of the key manager from the Registry).
 *
 * If @c keyManager is nil it uses the default key manager from the Registry.
 */
+ (nullable id<TINKMac>)primitiveWithKeysetHandle:(TINKKeysetHandle *)keysetHandle
                                    andKeyManager:
                                        (nullable TINKMacKeyManager<TINKKeyManager> *)keyManager
                                            error:(NSError **)error;

@end

NS_ASSUME_NONNULL_END
