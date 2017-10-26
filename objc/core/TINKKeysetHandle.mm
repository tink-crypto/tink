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
#import "objc/core/TINKKeysetHandle_Internal.h"

#include "cc/keyset_handle.h"
#include "proto/tink.pb.h"

#import "objc/util/TINKStrings.h"
#import "proto/Tink.pbobjc.h"

@implementation TINKKeysetHandle

- (instancetype)initWithKeyset:(TINKPBKeyset *)keyset {
  self = [super init];
  if (self) {
    // Serialize the Obj-C protocol buffer.
    std::string serializedKeyset = TINKPBSerializeToString(keyset, nil);

    // Deserialize it to a C++ protocol buffer.
    _ccKeysetPB = new google::crypto::tink::Keyset();
    if (!_ccKeysetPB || !_ccKeysetPB->ParseFromString(serializedKeyset)) {
      return nil;
    }

    _ccKeysetHandle = new crypto::tink::KeysetHandle(*_ccKeysetPB);
    if (!_ccKeysetHandle) {
      delete _ccKeysetPB;
      return nil;
    }

    _keyset = keyset;
  }
  return self;
}

- (void)dealloc {
  delete _ccKeysetHandle;
  delete _ccKeysetPB;
}

@end
