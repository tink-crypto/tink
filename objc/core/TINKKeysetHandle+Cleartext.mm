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

#import "objc/TINKKeysetHandle+Cleartext.h"

#include "tink/cleartext_keyset_handle.h"

#import "objc/TINKKeysetHandle.h"
#import "objc/core/TINKKeysetHandle_Internal.h"
#import "objc/core/TINKKeysetReader_Internal.h"
#import "objc/util/TINKErrors.h"
#import "objc/util/TINKStrings.h"

@implementation TINKKeysetHandle (Cleartext)

- (nullable instancetype)initCleartextKeysetHandleWithKeysetReader:(TINKKeysetReader *)reader
                                                             error:(NSError **)error {
  @synchronized(reader) {
    if (reader.used) {
      // A reader can only be used once.
      if (error) {
        *error = TINKStatusToError(
            crypto::tink::util::Status(absl::StatusCode::kResourceExhausted,
                                       "A KeysetReader can be used only once."));
      }
      return nil;
    }
    reader.used = YES;
  }
  auto st = crypto::tink::CleartextKeysetHandle::Read(reader.ccReader);
  if (!st.ok()) {
    if (error) {
      *error = TINKStatusToError(st.status());
    }
    return nil;
  }

  return [[TINKKeysetHandle alloc] initWithCCKeysetHandle:std::move(st.ValueOrDie())];
}

- (NSData *)serializedKeyset {
  auto keyset = crypto::tink::CleartextKeysetHandle::GetKeyset(*self.ccKeysetHandle);
  return TINKStringToNSData(keyset.SerializeAsString());
}

@end
