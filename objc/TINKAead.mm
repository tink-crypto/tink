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

#import "objc/TINKAead.h"
#import "objc/TINKAead_Internal.h"

#import "objc/util/TINKErrors.h"
#import "objc/util/TINKStrings.h"

#include "absl/strings/string_view.h"
#include "cc/aead.h"

@implementation TINKAead

- (instancetype)initWithPrimitive:(crypto::tink::Aead *)primitive {
  if (self = [super init]) {
    _primitive = primitive;
  }
  return self;
}

- (void)dealloc {
  delete _primitive;
}

- (NSData *)encrypt:(NSData *)plaintext
    withAdditionalData:(NSData *)additionalData
                 error:(NSError **)error {
  auto st = _primitive->Encrypt(
      absl::string_view(static_cast<const char *>(plaintext.bytes), plaintext.length),
      absl::string_view(static_cast<const char *>(additionalData.bytes),
                                    additionalData.length));
  if (!st.ok()) {
    *error = TINKStatusToError(st.status());
    return nil;
  }
  return TINKStringToNSData(st.ValueOrDie());
}

- (NSData *)decrypt:(NSData *)ciphertext
    withAdditionalData:(NSData *)additionalData
                 error:(NSError **)error {
  auto st = _primitive->Decrypt(
      absl::string_view(static_cast<const char *>(ciphertext.bytes), ciphertext.length),
      absl::string_view(static_cast<const char *>(additionalData.bytes),
                                    additionalData.length));
  if (!st.ok()) {
    *error = TINKStatusToError(st.status());
    return nil;
  }
  return TINKStringToNSData(st.ValueOrDie());
}

@end
