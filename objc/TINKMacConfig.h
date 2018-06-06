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
 * This class is used for registering with the Registry all instances of Mac key types supported in
 * a particular release of Tink.
 *
 * To register all Mac key types provided in Tink release 1.1.0 one can do:
 *
 * NSError *error = nil;
 * TINKMacConfig *macConfig = [TINKMacConfig alloc] initWithVersion:TINKVersion1_1_0
 *                                                            error:&error];
 * if (!macConfig || error) {
 *   // handle error.
 * }
 *
 * if (![TINKConfig registerConfig:macConfig error:&error]) {
 *   // handle error.
 * }
 *
 * For more information on the creation and usage of TINKMac instances see TINKMacFactory.
 */
@interface TINKMacConfig : TINKRegistryConfig

/* Use initWithVersion:error: to get an instance of TINKMacConfig. */
- (nullable instancetype)init NS_UNAVAILABLE;

/* Returns config of Mac implementations supported in given @c version of Tink. */
- (nullable instancetype)initWithVersion:(TINKVersion)version
                                   error:(NSError **)error NS_DESIGNATED_INITIALIZER;

@end

NS_ASSUME_NONNULL_END
