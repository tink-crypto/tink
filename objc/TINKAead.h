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

NS_ASSUME_NONNULL_BEGIN

/**
 * The interface for authenticated encryption with additional authenticated data. Implementations of
 * this interface are secure against adaptive chosen ciphertext attacks. Encryption with additional
 * data ensures authenticity and integrity of that data, but not its secrecy. (see RFC 5116,
 * https://tools.ietf.org/html/rfc5116)
 */
@protocol TINKAead <NSObject>

/**
 * Encrypts @c plaintext with @c additionalData as additional authenticated data, and returns the
 * resulting ciphertext. The ciphertext allows for checking authenticity and integrity of the
 * additional data, but does not guarantee its secrecy.
 *
 * @param plaintext       The data to encrypt.
 * @param additionalData  Additional authenticated data.
 * @return                The encrypted data on success; nil in case of error.
 */
- (nullable NSData *)encrypt:(NSData *)plaintext
          withAdditionalData:(NSData *)additionalData
                       error:(NSError **)error;

/**
 * Decrypts @c ciphertext with @c additionalData as additional authenticated data, and returns the
 * resulting plaintext. The decryption verifies the authenticity and integrity of the additional
 * data, but there are no guarantees with regards to secrecy of that data.
 *
 * @param ciphertext      The data to decrypt.
 * @param additionalData  Additional authenticated data.
 * @return                The decrypted data on success; nil in case of error.
 */
- (nullable NSData *)decrypt:(NSData *)ciphertext
          withAdditionalData:(NSData *)additionalData
                       error:(NSError **)error;

@end

NS_ASSUME_NONNULL_END
