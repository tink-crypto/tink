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
#import "objc/util/TINKErrors.h"

#include "absl/status/status.h"
#include "tink/util/status.h"

static NSString *const kTinkErrorDomain = @"TinkErrorDomain";

NSError *TINKStatusToError(const crypto::tink::util::Status &status) {
  NSString *errorMessage = [NSString stringWithUTF8String:((std::string)status.message()).c_str()];
  NSDictionary *userInfo = @{
    NSLocalizedDescriptionKey : NSLocalizedString(@"Tink Error", nil),
    NSLocalizedFailureReasonErrorKey : NSLocalizedString(errorMessage, nil),
  };
  return [NSError errorWithDomain:kTinkErrorDomain code:(NSInteger)status.code() userInfo:userInfo];
}

NSError *TINKError(crypto::tink::util::error::Code code, NSString *message) {
  NSDictionary *userInfo = @{
    NSLocalizedDescriptionKey : NSLocalizedString(@"Tink Error", nil),
    NSLocalizedFailureReasonErrorKey : NSLocalizedString(message, nil),
  };
  return [NSError errorWithDomain:kTinkErrorDomain code:code userInfo:userInfo];
}

NSError *TINKError(absl::StatusCode code, NSString *message) {
  NSDictionary *userInfo = @{
    NSLocalizedDescriptionKey : NSLocalizedString(@"Tink Error", nil),
    NSLocalizedFailureReasonErrorKey : NSLocalizedString(message, nil),
  };
  return [NSError errorWithDomain:kTinkErrorDomain code:(NSInteger)code userInfo:userInfo];
}
