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

@class TINKHybridDecryptKeyManager;
@protocol TINKKeyManager;

NS_ASSUME_NONNULL_BEGIN

/**
 * TINKHybridDecryptConfig offers convenience methods for initializing TINKHybridDecryptFactory and
 * the underlying Registry.INSTANCE. In particular, it allows for initializing the Registry with
 * native key types and their managers that Tink supports out of the box.
 *
 * For more information on how to obtain and use HybridDecrypt primitives see
 * TINKHybridDecryptFactory.
 */
@interface TINKHybridDecryptConfig : NSObject

/** Registers standard HybridDecrypt key types and their managers with the Registry. */
+ (BOOL)registerStandardKeyTypes;

@end

NS_ASSUME_NONNULL_END
