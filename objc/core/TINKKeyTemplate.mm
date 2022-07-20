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

#import "objc/TINKKeyTemplate.h"
#import "objc/core/TINKKeyTemplate_Internal.h"
#import "objc/util/TINKErrors.h"

#include "absl/status/status.h"
#include "tink/util/status.h"
#include "proto/tink.pb.h"

@implementation TINKKeyTemplate {
  google::crypto::tink::KeyTemplate *_ccKeyTemplate;
}

- (instancetype)initWithCcKeyTemplate:(google::crypto::tink::KeyTemplate *)ccKeyTemplate {
  if ((self = [super init])) {
    _ccKeyTemplate = ccKeyTemplate;
  }
  return self;
}

- (void)setCcKeyTemplate:(google::crypto::tink::KeyTemplate *)ccKeyTemplate {
  _ccKeyTemplate = ccKeyTemplate;
}

- (google::crypto::tink::KeyTemplate *)ccKeyTemplate {
  return _ccKeyTemplate;
}

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wobjc-designated-initializers"
- (instancetype)initWithKeyTemplate:(id)keyTemplate error:(NSError **)error {
  NSAssert(![self isMemberOfClass:[TINKKeyTemplate class]],
           @"Only instantiate from derived classes!");
  if (error) {
    *error =
        TINKError(absl::StatusCode::kInternal, @"Only instantiate from derived classes!");
  }
  return nil;
}
#pragma clang diagnostic pop

@end
