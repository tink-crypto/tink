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

#import "objc/signature/TINKPublicKeySignInternal.h"

#import "objc/TINKPublicKeySign.h"
#import "objc/util/TINKErrors.h"
#import "objc/util/TINKStrings.h"

#include "absl/strings/string_view.h"
#include "tink/public_key_sign.h"

@implementation TINKPublicKeySignInternal {
  std::unique_ptr<crypto::tink::PublicKeySign> _ccPublicKeySign;
}

- (instancetype)initWithCCPublicKeySign:
    (std::unique_ptr<crypto::tink::PublicKeySign>)ccPublicKeySign {
  if (self = [super init]) {
    _ccPublicKeySign = std::move(ccPublicKeySign);
  }
  return self;
}

- (void)dealloc {
  _ccPublicKeySign.reset();
}

- (NSData *)signatureForData:(NSData *)data error:(NSError **)error {
  auto st =
      _ccPublicKeySign->Sign(absl::string_view(static_cast<const char *>(data.bytes), data.length));
  if (!st.ok()) {
    if (error) {
      *error = TINKStatusToError(st.status());
    }
    return nil;
  }

  return TINKStringToNSData(st.value());
}

- (crypto::tink::PublicKeySign *)ccPublicKeySign {
  if (!_ccPublicKeySign) {
    return nil;
  }
  return _ccPublicKeySign.get();
}

@end
