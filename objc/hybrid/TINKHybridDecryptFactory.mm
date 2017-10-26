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

#import "objc/hybrid/TINKHybridDecryptFactory.h"

#include "cc/hybrid/hybrid_decrypt_factory.h"
#include "cc/hybrid_decrypt.h"
#include "cc/key_manager.h"
#include "cc/keyset_handle.h"
#include "cc/util/status.h"
#include "proto/tink.pb.h"

#import "objc/TINKHybridDecrypt.h"
#import "objc/TINKKeyManager.h"
#import "objc/TINKKeysetHandle.h"
#import "objc/core/TINKKeysetHandle_Internal.h"
#import "objc/hybrid/TINKHybridDecryptInternal.h"
#import "objc/hybrid/TINKHybridDecryptKeyManager.h"
#import "objc/hybrid/TINKHybridDecryptKeyManager_Internal.h"
#import "objc/util/TINKErrors.h"

@implementation TINKHybridDecryptFactory

+ (id<TINKHybridDecrypt>)primitiveWithKeysetHandle:(TINKKeysetHandle *)keysetHandle
                                             error:(NSError **)error {
  return [TINKHybridDecryptFactory primitiveWithKeysetHandle:keysetHandle
                                               andKeyManager:nil
                                                       error:error];
}

+ (id<TINKHybridDecrypt>)primitiveWithKeysetHandle:(TINKKeysetHandle *)keysetHandle
                                     andKeyManager:
                                         (TINKHybridDecryptKeyManager<TINKKeyManager> *)keyManager
                                             error:(NSError **)error {
  if (error) {
    *error = nil;
  }

  crypto::tink::KeysetHandle *ccHandle = [keysetHandle ccKeysetHandle];

  crypto::tink::KeyManager<crypto::tink::HybridDecrypt> *ccKeyManager = nullptr;
  if (keyManager) {
    ccKeyManager = keyManager.ccKeyManager;
  }

  auto ccHybridDecrypt = crypto::tink::HybridDecryptFactory::GetPrimitive(*ccHandle, ccKeyManager);
  if (!ccHybridDecrypt.ok()) {
    if (error) {
      *error = TINKStatusToError(ccHybridDecrypt.status());
    }
    return nil;
  }

  auto ccPrimitive = ccHybridDecrypt.ValueOrDie().release();

  // Wrap the C++ HybridDecrypt primitive into a TINKHybridDecrypt Obj-C instance.
  id<TINKHybridDecrypt> objcHybridDecrypt =
      [[TINKHybridDecryptInternal alloc] initWithPrimitive:ccPrimitive];
  if (!objcHybridDecrypt) {
    if (error) {
      *error = TINKStatusToError(
          crypto::tink::util::Status(
              crypto::tink::util::error::RESOURCE_EXHAUSTED,
              "Cannot initialize TINKHybridDecrypt"));
    }
    return nil;
  }

  return objcHybridDecrypt;
}

@end
