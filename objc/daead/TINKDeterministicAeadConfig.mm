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

#import "TINKDeterministicAeadConfig.h"

#include "tink/daead/deterministic_aead_config.h"
#include "tink/util/status.h"
#include "proto/config.pb.h"

#import "TINKRegistryConfig.h"
#import "core/TINKRegistryConfig_Internal.h"
#import "util/TINKErrors.h"

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wobjc-designated-initializers"
@implementation TINKDeterministicAeadConfig

- (nullable instancetype)initWithError:(NSError **)error {
  auto st = crypto::tink::DeterministicAeadConfig::Register();
  if (!st.ok()) {
    if (error) {
      *error = TINKStatusToError(st);
    }
    return nil;
  }

  google::crypto::tink::RegistryConfig ccConfig = crypto::tink::DeterministicAeadConfig::Latest();
  return (self = [super initWithCcConfig:ccConfig]);
}

@end
#pragma clang diagnostic pop
