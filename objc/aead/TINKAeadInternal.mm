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

#import "objc/aead/TINKAeadInternal.h"

#import "objc/TINKAead.h"
#import "objc/util/TINKErrors.h"
#import "objc/util/TINKStrings.h"

#include "absl/strings/string_view.h"
#include "tink/aead.h"

@implementation TINKAeadInternal {
  std::unique_ptr<crypto::tink::Aead> _ccAead;
}

- (instancetype)initWithCCAead:(std::unique_ptr<crypto::tink::Aead>)ccAead {
  self = [super init];
  if (self) {
    _ccAead = std::move(ccAead);
  }
  return self;
}

- (void)dealloc {
  _ccAead.reset();
}

- (NSData *)encrypt:(NSData *)plaintext
    withAdditionalData:(NSData *)additionalData
                 error:(NSError **)error {
  absl::string_view ccAdditionalData;
  if (additionalData && additionalData.length > 0) {
    ccAdditionalData =
        absl::string_view(static_cast<const char *>(additionalData.bytes), additionalData.length);
  }

  auto st = _ccAead->Encrypt(
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

- (NSData *)decrypt:(NSData *)ciphertext
    withAdditionalData:(NSData *)additionalData
                 error:(NSError **)error {
  absl::string_view ccAdditionalData;
  if (additionalData && additionalData.length > 0) {
    ccAdditionalData =
        absl::string_view(static_cast<const char *>(additionalData.bytes), additionalData.length);
  }

  auto st = _ccAead->Decrypt(
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

- (nullable crypto::tink::Aead *)ccAead {
  if (!_ccAead) {
    return nil;
  }
  return _ccAead.get();
}

@end
