/**
 * Copyright 2018 Google Inc.
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
@protocol TINKPublicKeyVerify;

NS_ASSUME_NONNULL_BEGIN;

/**
 * TINKPublicKeyVerifyFactory allows for obtaining a TINKPublicKeyVerify primitive from a
 * TINKKeysetHandle.
 *
 * TINKPublicKeyVerifyFactory gets primitives from the Registry, which can be initialized via
 * convenience methods from the TINKSignatureConfig class. Here is an example how one can obtain and
 * use a TINKPublicKeyVerify primitive:
 *
 * NSError *error = nil;
 * TINKSignatureConfig *signatureConfig = [[TINKSignatureConfig alloc] initWithError:&error];
 * if (!signatureConfig || error) {
 *   // handle error.
 * }
 *
 * if (![TINKConfig registerConfig:signatureConfig error:&error]) {
 *   // handle error.
 * }
 *
 * TINKKeysetHandle keysetHandle = ...;
 * id<TINKPublicKeyVerify> publicKeyVerify = [TINKPublicKeyVerifyFactory
 *                                               primitiveWithKeysetHandle:keysetHandle
 *                                                                   error:&error];
 * if (!publicKeyVerify || error) {
 *   // handle error.
 * }
 *
 * NSData *data = ...;
 * NSData *signature = ...;
 * BOOL result = [publicKeyVerify verifySignature:signature forData:data error:&error];
 * if (!result) {
 *   // Signature was not correct.
 *   // ...
 * }
 */
@interface TINKPublicKeyVerifyFactory : NSObject
/**
 * Returns an object that conforms to the TINKPublicKeyVerify protocol. It uses key material from
 * the keyset specified via @c keysetHandle.
 */
+ (nullable id<TINKPublicKeyVerify>)primitiveWithKeysetHandle:(TINKKeysetHandle *)keysetHandle
                                                        error:(NSError **)error;
@end

NS_ASSUME_NONNULL_END;
