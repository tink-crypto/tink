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

@class TINKRegistryConfig;

NS_ASSUME_NONNULL_BEGIN

/**
 * Static methods for handling of Tink configurations.
 *
 * Configurations, i.e., collections of key types and their corresponding key managers supported by
 * a specific run-time environment enable control of Tink setup via JSON-formatted config files that
 * determine which key types are supported, and provide a mechanism for deprecation of
 * obsolete/outdated cryptographic schemes (see tink/proto/config.proto for more info).
 *
 * Example usage:
 *
 * NSError *error = nil;
 * TINKAllConfig *config = [[TINKAllConfig alloc] initWithError:&error];
 * if (!config || error) {
 *   // handle error.
 * }
 *
 * if (![TINKConfig registerConfig:config error:&error]) {
 *   // handle error.
 * }
 */
@interface TINKConfig : NSObject

/* Registers key managers according to the specification in @c config. */
+ (BOOL)registerConfig:(TINKRegistryConfig *)config error:(NSError **)error;

@end

NS_ASSUME_NONNULL_END
