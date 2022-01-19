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

#ifdef __cplusplus

#import "objc/TINKMac.h"

#import <Foundation/Foundation.h>

#include "tink/mac.h"

NS_ASSUME_NONNULL_BEGIN

/**
 * This interface is internal-only. Use TINKMacFactory to get an instance that conforms to
 * TINKMac.
 */
@interface TINKMacInternal : NSObject <TINKMac>

- (instancetype)init NS_UNAVAILABLE;

- (nullable instancetype)initWithCCMac:(std::unique_ptr<crypto::tink::Mac>)ccMac
    NS_DESIGNATED_INITIALIZER;

- (nullable crypto::tink::Mac *)ccMac;

@end

NS_ASSUME_NONNULL_END

#endif  // __cplusplus
