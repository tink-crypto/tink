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
#import "objc/TINKKeyManager.h"
#import "objc/mac/TINKMacKeyManager.h"

@class TINKPBKeyData;
@class TINKPBHmacKey;
@class TINKPBKeyTemplate;
@protocol TINKMac;

NS_ASSUME_NONNULL_BEGIN
@interface TINKHmacKeyManager : TINKMacKeyManager <TINKKeyManager>

/** The version of this key manager. */
@property(nonatomic, readonly) NSUInteger version;

/** The key type handled by this manager. */
@property(nonatomic, readonly) NSString *keyType;

/** Constructs an instance of HMAC-Mac for the given @c keyData. */
- (nullable id<TINKMac>)primitiveFromKeyData:(TINKPBKeyData *)keyData error:(NSError **)error;

/** Constructs an instance of HMAC-Mac for the given @c key. */
- (nullable id<TINKMac>)primitiveFromKey:(TINKPBHmacKey *)key error:(NSError **)error;

/**
 * Generates a new random TINKPBHmacKey, based on the specified @c keyTemplate which must contain
 * HmacKeyFormat-proto.
 */
- (nullable TINKPBHmacKey *)newKeyFromTemplate:(TINKPBKeyTemplate *)keyTemplate
                                         error:(NSError **)error;

/** True if the key manager supports the supplied @c keyType. */
- (BOOL)shouldSupportKeyType:(NSString *)keyType;

@end
NS_ASSUME_NONNULL_END
