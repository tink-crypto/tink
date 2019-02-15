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
 * Protocol for Deterministic Authenticated Encryption with Associated Data (Deterministic AEAD).
 *
 * For why this protocol is desirable and some of its use cases, see for example
 * RFC 5297 section 1.3 (https://tools.ietf.org/html/rfc5297#section-1.3).
 *
 * Warning
 *
 * Unlike Aead, implementations of this protocol are not semantically secure, because
 * encrypting the same plaintex always yields the same ciphertext.
 *
 * Security guarantees
 *
 * Implementations of this protocol provide 128-bit security level against multi-user attacks
 * with up to 2^32 keys. That means if an adversary obtains 2^32 ciphertexts of the same message
 * encrypted under 2^32 keys, they need to do 2^128 computations to obtain a single key.
 *
 * Encryption with associated data ensures authenticity (who the sender is) and integrity (the
 * data has not been tampered with) of that data, but not its secrecy. See RFC 5116 (
 * https://tools.ietf.org/html/rfc5116)
 */
@protocol TINKDeterministicAead <NSObject>

/**
 * Deterministically encrypts @c plaintext with @c associatedData as associated
 * authenticated data.
 *
 * Warning
 *
 * Encrypting the same @c plaintext multiple times protects the integrity of that plaintext, but
 * confidentiality is compromised to the extent that an attacker can determine that the same
 * plaintext was encrypted.
 *
 * The resulting ciphertext allows for checking authenticity and integrity of @c associatedData, but
 * does not guarantee its secrecy.
 *
 * @param plaintext       The data to encrypt.
 * @param associatedData  Additional associated data. (optional)
 * @return                The encrypted data on success; nil in case of error.
 */
- (nullable NSData *)encryptDeterministically:(NSData *)plaintext
                           withAssociatedData:(nullable NSData *)associatedData
                                        error:(NSError **)error;

/**
 * Deterministically decrypts @c ciphertext with @c associatedData as associated authenticated data.
 *
 * The decryption verifies the authenticity and integrity of the associated data, but there are no
 * guarantees with regards to secrecy of that data.
 *
 * @param ciphertext      The data to decrypt.
 * @param associatedData  Associated authenticated data. (optional)
 * @return                The decrypted data on success; nil in case of error.
 */
- (nullable NSData *)decryptDeterministically:(NSData *)ciphertext
                           withAssociatedData:(nullable NSData *)associatedData
                                        error:(NSError **)error;

@end

NS_ASSUME_NONNULL_END
