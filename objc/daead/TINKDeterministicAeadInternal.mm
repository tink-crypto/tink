/**
 * Copyright 2019 Google Inc.
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

#import "objc/daead/TINKDeterministicAeadInternal.h"
#import "objc/TINKDeterministicAead.h"

#include "absl/strings/string_view.h"
#include "tink/deterministic_aead.h"
#include "tink/keyset_handle.h"
#include "tink/util/status.h"

#import "objc/TINKKeysetHandle.h"
#import "objc/core/TINKKeysetHandle_Internal.h"
#import "objc/util/TINKErrors.h"
#import "objc/util/TINKStrings.h"

@implementation TINKDeterministicAeadInternal {
  std::unique_ptr<crypto::tink::DeterministicAead> _ccDeterministicAead;
}

- (instancetype)initWithCCDeterministicAead:
    (std::unique_ptr<crypto::tink::DeterministicAead>)ccDeterministicAead {
  self = [super init];
  if (self) {
    _ccDeterministicAead = std::move(ccDeterministicAead);
  }
  return self;
}

- (void)dealloc {
  _ccDeterministicAead.reset();
}

- (NSData *)encryptDeterministically:(NSData *)plaintext
                  withAssociatedData:(NSData *)additionalData
                               error:(NSError **)error {
  absl::string_view ccAdditionalData;
  if (additionalData && additionalData.length > 0) {
    ccAdditionalData =
        absl::string_view(static_cast<const char *>(additionalData.bytes), additionalData.length);
  }

  auto st = _ccDeterministicAead->EncryptDeterministically(
      absl::string_view(static_cast<const char *>(plaintext.bytes), plaintext.length),
      ccAdditionalData);
  if (!st.ok()) {
    if (error) {
      *error = TINKStatusToError(st.status());
    }
    return nil;
  }

  return TINKStringToNSData(st.value());
}

- (NSData *)decryptDeterministically:(NSData *)ciphertext
                  withAssociatedData:(NSData *)additionalData
                               error:(NSError **)error {
  absl::string_view ccAdditionalData;
  if (additionalData && additionalData.length > 0) {
    ccAdditionalData =
        absl::string_view(static_cast<const char *>(additionalData.bytes), additionalData.length);
  }

  auto st = _ccDeterministicAead->DecryptDeterministically(
      absl::string_view(static_cast<const char *>(ciphertext.bytes), ciphertext.length),
      ccAdditionalData);
  if (!st.ok()) {
    if (error) {
      *error = TINKStatusToError(st.status());
    }
    return nil;
  }

  return TINKStringToNSData(st.value());
}

- (nullable crypto::tink::DeterministicAead *)ccDeterministicAead {
  if (!_ccDeterministicAead) {
    return nil;
  }
  return _ccDeterministicAead.get();
}

@end
