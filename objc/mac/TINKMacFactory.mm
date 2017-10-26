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

#import "objc/mac/TINKMacFactory.h"

#import "objc/TINKKeyManager.h"
#import "objc/TINKKeysetHandle.h"
#import "objc/TINKMac.h"
#import "objc/core/TINKKeysetHandle_Internal.h"
#import "objc/mac/TINKMacInternal.h"
#import "objc/mac/TINKMacKeyManager.h"
#import "objc/mac/TINKMacKeyManager_Internal.h"
#import "objc/util/TINKErrors.h"

#include "cc/key_manager.h"
#include "cc/keyset_handle.h"
#include "cc/mac.h"
#include "cc/mac/mac_factory.h"
#include "cc/util/status.h"
#include "proto/tink.pb.h"

@implementation TINKMacFactory

+ (id<TINKMac>)primitiveWithKeysetHandle:(TINKKeysetHandle *)keysetHandle error:(NSError **)error {
  return [TINKMacFactory primitiveWithKeysetHandle:keysetHandle andKeyManager:nil error:error];
}

+ (nullable id<TINKMac>)primitiveWithKeysetHandle:(TINKKeysetHandle *)keysetHandle
                                    andKeyManager:(TINKMacKeyManager<TINKKeyManager> *)keyManager
                                            error:(NSError **)error {
  if (error) {
    *error = nil;
  }

  crypto::tink::KeysetHandle *ccHandle = [keysetHandle ccKeysetHandle];

  crypto::tink::KeyManager<crypto::tink::Mac> *ccKeyManager = nullptr;
  if (keyManager) {
    ccKeyManager = keyManager.ccKeyManager;
  }

  auto ccMac = crypto::tink::MacFactory::GetPrimitive(*ccHandle, ccKeyManager);
  if (!ccMac.ok()) {
    if (error) {
      *error = TINKStatusToError(ccMac.status());
    }
    return nil;
  }

  auto ccPrimitive = ccMac.ValueOrDie().release();

  // Wrap the C++ Mac primitive into a TINKMac Obj-C instance.
  id<TINKMac> objcMac = [[TINKMacInternal alloc] initWithPrimitive:ccPrimitive];
  if (!objcMac) {
    if (error) {
      *error = TINKStatusToError(
          crypto::tink::util::Status(
              crypto::tink::util::error::RESOURCE_EXHAUSTED, "Cannot initialize TINKMac"));
    }
    return nil;
  }

  return objcMac;
}

@end
