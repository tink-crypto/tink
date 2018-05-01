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

#import "objc/mac/TINKMacConfig.h"

#import "objc/TINKRegistryConfig.h"
#import "objc/TINKVersion.h"
#import "objc/core/TINKRegistryConfig_Internal.h"
#import "objc/util/TINKErrors.h"

#include "tink/mac/mac_config.h"
#include "tink/util/status.h"
#include "proto/config.pb.h"

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wobjc-designated-initializers"
@implementation TINKMacConfig

- (instancetype)initWithVersion:(TINKVersion)version error:(NSError **)error {
  auto st = crypto::tink::MacConfig::Init();
  if (!st.ok()) {
    if (error) {
      *error = TINKStatusToError(st);
    }
    return nil;
  }

  google::crypto::tink::RegistryConfig ccConfig;
  switch (version) {
    case TINKVersion1_1_0:
      ccConfig = crypto::tink::MacConfig::Tink_1_1_0();
      break;
    default:
      if (error) {
        *error = TINKStatusToError(crypto::tink::util::Status(
            crypto::tink::util::error::INVALID_ARGUMENT, "Unsupported Tink version."));
      }
      return nil;
  }

  return (self = [super initWithCcConfig:ccConfig]);
}

@end
#pragma clang diagnostic pop
