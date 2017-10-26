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

@class TINKAead;
@class TINKKeysetHandle;

/**
 * TINKAeadFactory allows obtaining a primitive from a TINKKeysetHandle.
 *
 * TINKAeadFactory gets primitives from the Registry. The factory allows initalizing the Registry
 * with native key types and their managers that Tink supports out of the box. These key types are
 * divided in two groups:
 *
 *  - standard: secure and safe to use in new code. Over time, with new developments in
 *    cryptanalysis and computing power, some standard key types might become legacy.
 *
 *  - legacy: deprecated and insecure or obsolete, should not be used in new code. Existing users
 *    should upgrade to one of the standard key types.
 *
 * This divison allows for gradual retiring insecure or obsolete key types.
 *
 * For example, here is how one can obtain and use an Aead primitive:
 *
 * NSError *error = nil;
 * [TINKAeadConfig registerStandardKeyTypes];
 * TINKKeysetHandle *handle = [TINKKeysetHandle initWithKeyset:keyset];
 * TINKAead *aead = [TINKAeadFactory primitiveWithKeysetHandle:handle error:&error];
 * if (error) {
 *   // handle error
 * }
 *
 * NSString *plaintext = ...;
 * NSString *data = ...;
 * error = nil;
 * NSString *ciphertext = [aead encrypt:plaintext withAdditionalData:data error:&error];
 * if (error) {
 *   // handle error
 * }
 */
@interface TINKAeadFactory : NSObject

/**
 * Returns an Aead-primitive that uses key material from the keyset specified via @c keysetHandle.
 */
+ (nullable TINKAead *)primitiveWithKeysetHandle:(nonnull TINKKeysetHandle *)keysetHandle
                                           error:(NSError *_Nullable *_Nonnull)error;

/**
 * Returns an Aead-primitive that uses key material from the keyset specified via @c keysetHandle
 * and is instantiated by the given @c customKeyManager (instead of the key manager from the
 * Registry).
 */
+ (nullable TINKAead *)primitiveWithKeysetHandle:(nonnull TINKKeysetHandle *)keysetHandle
                                   andKeyManager:(nullable NSObject *)keyManager
                                           error:(NSError *_Nullable *_Nonnull)error NS_UNAVAILABLE;

@end
