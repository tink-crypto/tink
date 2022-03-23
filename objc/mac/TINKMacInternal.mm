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

#import "objc/mac/TINKMacInternal.h"

#import "objc/util/TINKErrors.h"
#import "objc/util/TINKStrings.h"

#include "absl/strings/string_view.h"
#include "tink/mac.h"

@implementation TINKMacInternal {
  std::unique_ptr<crypto::tink::Mac> _ccMac;
}

- (instancetype)initWithCCMac:(std::unique_ptr<crypto::tink::Mac>)ccMac {
  if (self = [super init]) {
    _ccMac = std::move(ccMac);
  }
  return self;
}

- (void)dealloc {
  _ccMac.reset();
}

- (NSData *)computeMacForData:(NSData *)data error:(NSError **)error {
  auto st =
      _ccMac->ComputeMac(absl::string_view(static_cast<const char *>(data.bytes), data.length));
  if (!st.ok()) {
    if (error) {
      *error = TINKStatusToError(st.status());
    }
    return nil;
  }

  return TINKStringToNSData(st.value());
}

- (BOOL)verifyMac:(NSData *)mac forData:(NSData *)data error:(NSError **)error {
  auto st =
      _ccMac->VerifyMac(absl::string_view(static_cast<const char *>(mac.bytes), mac.length),
                        absl::string_view(static_cast<const char *>(data.bytes), data.length));
  if (!st.ok()) {
    if (error) {
      *error = TINKStatusToError(st);
    }
    return NO;
  }
  return YES;
}

- (nullable crypto::tink::Mac *)ccMac {
  if (!_ccMac) {
    return nil;
  }
  return _ccMac.get();
}

@end
