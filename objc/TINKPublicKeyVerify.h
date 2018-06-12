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

NS_ASSUME_NONNULL_BEGIN

/**
 * Protocol for public key verifying.
 * Digital Signatures provide functionality of signing data and verification of the signatures.
 * They are represented by a pair of primitives PublicKeySign for signing of data, and
 * PublicKeyVerify for verification of signatures. Implementations of these interfaces are secure
 * against adaptive chosen-message attacks. Signing data ensures the authenticity and the integrity
 * of that data, but not its secrecy.
 */
@protocol TINKPublicKeyVerify <NSObject>

/**
 * Verifies that @c signature is a digital signature for @c data.
 *
 * @param signature  The signature to be verified.
 * @param data       The data for which to verify the signature.
 * @param error      non-nil in case of error.
 * @return           YES if the signature is valid, NO otherwise.
 */
- (BOOL)verifySignature:(NSData *)signature forData:(NSData *)data error:(NSError **)error;

@end

NS_ASSUME_NONNULL_END
