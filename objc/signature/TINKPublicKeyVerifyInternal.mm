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

#import "signature/TINKPublicKeyVerifyInternal.h"

#import "TINKPublicKeyVerify.h"
#import "util/TINKErrors.h"
#import "util/TINKStrings.h"

#include "absl/strings/string_view.h"
#include "tink/public_key_verify.h"

@implementation TINKPublicKeyVerifyInternal {
  std::unique_ptr<crypto::tink::PublicKeyVerify> _ccPublicKeyVerify;
}

- (instancetype)initWithCCPublicKeyVerify:
    (std::unique_ptr<crypto::tink::PublicKeyVerify>)ccPublicKeyVerify {
  if (self = [super init]) {
    _ccPublicKeyVerify = std::move(ccPublicKeyVerify);
  }
  return self;
}

- (void)dealloc {
  _ccPublicKeyVerify.reset();
}

- (BOOL)verifySignature:(NSData *)signature forData:(NSData *)data error:(NSError **)error {
  auto st = _ccPublicKeyVerify->Verify(
      absl::string_view(static_cast<const char *>(signature.bytes), signature.length),
      absl::string_view(static_cast<const char *>(data.bytes), data.length));
  if (!st.ok()) {
    if (error) {
      *error = TINKStatusToError(st);
    }
  }
  return st.ok();
}

- (crypto::tink::PublicKeyVerify *)ccPublicKeyVerify {
  if (!_ccPublicKeyVerify) {
    return nil;
  }
  return _ccPublicKeyVerify.get();
}

@end
