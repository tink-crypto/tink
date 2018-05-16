/**
 * Copyright 2018 Google Inc.
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

#import "objc/util/TINKProtoHelpers.h"

#import "objc/util/TINKErrors.h"
#import "objc/util/TINKStrings.h"
#import "proto/Tink.pbobjc.h"

#include "tink/util/status.h"
#include "proto/tink.pb.h"

TINKPBKeyTemplate *TINKKeyTemplateToObjc(google::crypto::tink::KeyTemplate *ccKeyTemplate,
                                         NSError **error) {
  // Serialize it to std::string.
  std::string serializedKeyTemplate;
  if (!ccKeyTemplate->SerializeToString(&serializedKeyTemplate)) {
    if (error) {
      *error = TINKStatusToError(crypto::tink::util::Status(
          crypto::tink::util::error::INVALID_ARGUMENT, "Could not serialize C++ KeyTemplate."));
    }
    return nil;
  }

  // Deserialize it to an Obj-C TINKPBKeyTemplate.
  NSError *parseError = nil;
  TINKPBKeyTemplate *keyTemplate =
      [TINKPBKeyTemplate parseFromData:TINKStringToNSData(serializedKeyTemplate) error:&parseError];
  if (parseError) {
    if (error) {
      *error = parseError;
    }
    return nil;
  }

  return keyTemplate;
}
