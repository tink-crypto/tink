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

#import "objc/TINKRegistryConfig.h"
#import "objc/TINKVersion.h"

NS_ASSUME_NONNULL_BEGIN

/**
 * Static methods for registering with the Registry all instances of Tink key types supported in a
 * particular release of Tink. To register all Tink key types provided in Tink release 1.1.0 one can
 * do:
 *
 * NSError *error = nil;
 * TINKAllConfig *allConfig = [[TINKAllConfig alloc] initWithVersion:TINKVersion1_1_0 error:&error];
 * if (error || !allConfig) {
 *   // handle error.
 * }
 *
 * if (![TINKConfig registerConfig:allConfig error:&error]) {
 *   // handle error.
 * }
 */
@interface TINKAllConfig : TINKRegistryConfig

/** Use initWithVersion:error: to get an instance of TINKAllConfig. */
- (nullable instancetype)init NS_UNAVAILABLE;

- (nullable instancetype)initWithVersion:(TINKVersion)version
                                   error:(NSError **)error NS_DESIGNATED_INITIALIZER;

@end

NS_ASSUME_NONNULL_END
