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

@class TINKPBKeyData;
@class TINKPBKeyTemplate;

NS_ASSUME_NONNULL_BEGIN
/**
 * TINKKeyManager "understands" keys of specific key types: it can generate keys of a supported type
 * and create primitives for supported keys. A key type is identified by the global name of the
 * protocol buffer that holds the corresponding key material and is given by type_url-field of
 * KeyData-protocol buffer.
 */
@protocol TINKKeyManager

/** The version of this key manager. */
@property(nonatomic, readonly) NSUInteger version;

/** The type url identifying the key type handled by this manager. */
@property(nonatomic, readonly) NSString *keyType;

/** Constructs an instance of a primitive for the given @c keyData. */
- (nullable id)primitiveFromKeyData:(TINKPBKeyData *)keyData error:(NSError **)error;

/** Constructs an instance of a primitive for the given @c key. */
- (nullable id)primitiveFromKey:(id)key error:(NSError **)error;

/** Generates a new random key, based on the specified @c keyTemplate. */
- (nullable id)newKeyFromTemplate:(TINKPBKeyTemplate *)keyTemplate error:(NSError **)error;

/** True if the key manager supports the supplied @c keyType. */
- (BOOL)shouldSupportKeyType:(NSString *)keyType;

@end
NS_ASSUME_NONNULL_END
