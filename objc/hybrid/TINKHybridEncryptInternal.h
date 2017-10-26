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
#import "objc/TINKHybridEncrypt.h"

#include "cc/hybrid_encrypt.h"

/**
 * This interface is internal-only. Use TINKHybridEncryptFactory to get an instance that conforms to
 * TINKHybridEncrypt.
 */
@interface TINKHybridEncryptInternal : NSObject <TINKHybridEncrypt>

@property(nonatomic, nonnull, readonly) crypto::tink::HybridEncrypt* primitive;

- (nullable instancetype)init NS_UNAVAILABLE;

- (nullable instancetype)initWithPrimitive:(nonnull crypto::tink::HybridEncrypt*)primitive
    NS_DESIGNATED_INITIALIZER;

@end
