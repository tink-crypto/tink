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

#import "objc/TINKKeysetHandle.h"

#include "cc/keyset_handle.h"
#include "cc/util/status.h"
#include "proto/tink.pb.h"

#import "objc/TINKAead.h"
#import "objc/TINKAead_Internal.h"
#import "objc/TINKKeysetReader.h"
#import "objc/core/TINKKeysetReader_Internal.h"
#import "objc/util/TINKErrors.h"
#import "objc/util/TINKStrings.h"
#import "proto/Tink.pbobjc.h"

@implementation TINKKeysetHandle {
  std::unique_ptr<crypto::tink::KeysetHandle> _ccKeysetHandle;
}

- (instancetype)initWithCCKeysetHandle:(std::unique_ptr<crypto::tink::KeysetHandle>)ccKeysetHandle {
  self = [super init];
  if (self) {
    _ccKeysetHandle = std::move(ccKeysetHandle);
  }
  return self;
}

- (void)dealloc {
  _ccKeysetHandle.reset();
}

- (nullable instancetype)initWithKeysetReader:(TINKKeysetReader *)reader
                                       andKey:(TINKAead *)aeadKey
                                        error:(NSError **)error {
  crypto::tink::Aead *ccAead = aeadKey.primitive;

  // KeysetHandle::Read takes ownership of reader.ccReader.
  auto st = crypto::tink::KeysetHandle::Read(reader.ccReader, *ccAead);
  if (!st.ok()) {
    if (error) {
      *error = TINKStatusToError(st.status());
      return nil;
    }
  }

  return [self initWithCCKeysetHandle:std::move(st.ValueOrDie())];
}

- (nullable instancetype)initWithKeyTemplate:(TINKPBKeyTemplate *)keyTemplate
                                       error:(NSError **)error {
  // Serialize the Obj-C protocol buffer.
  std::string serializedKeyTemplate = TINKPBSerializeToString(keyTemplate, error);
  if (serializedKeyTemplate.empty()) {
    return nil;
  }

  // Deserialize it to a C++ protocol buffer.
  google::crypto::tink::KeyTemplate ccKeyTemplate;
  if (!ccKeyTemplate.ParseFromString(serializedKeyTemplate)) {
    if (error) {
      *error = TINKStatusToError(crypto::tink::util::Status(
          crypto::tink::util::error::INVALID_ARGUMENT, "Could not parse keyTemplate."));
    }
    return nil;
  }

  auto st = crypto::tink::KeysetHandle::GenerateNew(ccKeyTemplate);
  if (!st.ok()) {
    if (error) {
      *error = TINKStatusToError(st.status());
    }
    return nil;
  }

  return [self initWithCCKeysetHandle:std::move(st.ValueOrDie())];
}

- (crypto::tink::KeysetHandle *)ccKeysetHandle {
  return _ccKeysetHandle.get();
}

- (void)setCcKeysetHandle:(std::unique_ptr<crypto::tink::KeysetHandle>)handle {
  _ccKeysetHandle = std::move(handle);
}

@end
