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

#import "objc/TINKKeysetHandle+NoSecret.h"

#include "tink/no_secret_keyset_handle.h"

#import "objc/TINKKeysetHandle.h"
#import "objc/core/TINKKeysetHandle_Internal.h"
#import "objc/core/TINKKeysetReader_Internal.h"
#import "objc/util/TINKErrors.h"

@implementation TINKKeysetHandle (NoSecret)

- (nullable instancetype)initNoSecretKeysetHandleWithKeysetReader:(TINKKeysetReader *)reader
                                                            error:(NSError **)error {
  @synchronized(reader) {
    if (reader.used) {
      // A reader can only be used once.
      if (error) {
        *error = TINKStatusToError(
            crypto::tink::util::Status(crypto::tink::util::error::RESOURCE_EXHAUSTED,
                                       "A KeysetReader can be used only once."));
      }
      return nil;
    }
    reader.used = YES;
  }

  auto read_result = reader.ccReader.get()->Read();
  if (!read_result.ok()) {
    if (error) {
      *error = TINKStatusToError(read_result.status());
    }
    return nil;
  }

  auto st = crypto::tink::NoSecretKeysetHandle::Get(*std::move(read_result.ValueOrDie()));
  if (!st.ok()) {
    if (error) {
      *error = TINKStatusToError(st.status());
    }
    return nil;
  }

  return [[TINKKeysetHandle alloc] initWithCCKeysetHandle:std::move(st.ValueOrDie())];
}

@end
