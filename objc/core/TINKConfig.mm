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

#import "objc/TINKConfig.h"

#import <Foundation/Foundation.h>

#import "objc/TINKRegistryConfig.h"
#import "objc/core/TINKRegistryConfig_Internal.h"
#import "objc/util/TINKErrors.h"
#import "objc/util/TINKStrings.h"
#import "proto/Config.pbobjc.h"

#include "cc/config.h"
#include "cc/util/errors.h"
#include "proto/config.pb.h"

@implementation TINKConfig

+ (BOOL)registerConfig:(TINKRegistryConfig *)config error:(NSError **)error {
  auto st = crypto::tink::Config::Register(config.ccConfig);
  if (!st.ok()) {
    if (error) {
      *error = TINKStatusToError(st);
    }
    return NO;
  }

  return YES;
}

@end
