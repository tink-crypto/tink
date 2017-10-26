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

#import "objc/hybrid/TINKHybridEncryptFactory.h"

#include "cc/hybrid/hybrid_encrypt_factory.h"
#include "cc/hybrid_encrypt.h"
#include "cc/key_manager.h"
#include "cc/keyset_handle.h"
#include "cc/util/status.h"
#include "proto/tink.pb.h"

#import "objc/TINKHybridEncrypt.h"
#import "objc/TINKKeyManager.h"
#import "objc/TINKKeysetHandle.h"
#import "objc/core/TINKKeysetHandle_Internal.h"
#import "objc/hybrid/TINKHybridEncryptInternal.h"
#import "objc/hybrid/TINKHybridEncryptKeyManager.h"
#import "objc/hybrid/TINKHybridEncryptKeyManager_Internal.h"
#import "objc/util/TINKErrors.h"

@implementation TINKHybridEncryptFactory

+ (id<TINKHybridEncrypt>)primitiveWithKeysetHandle:(TINKKeysetHandle *)keysetHandle
                                             error:(NSError **)error {
  return [TINKHybridEncryptFactory primitiveWithKeysetHandle:keysetHandle
                                               andKeyManager:nil
                                                       error:error];
}

+ (id<TINKHybridEncrypt>)primitiveWithKeysetHandle:(TINKKeysetHandle *)keysetHandle
                                     andKeyManager:
                                         (TINKHybridEncryptKeyManager<TINKKeyManager> *)keyManager
                                             error:(NSError **)error {
  if (error) {
    *error = nil;
  }

  crypto::tink::KeysetHandle *ccHandle = [keysetHandle ccKeysetHandle];

  crypto::tink::KeyManager<crypto::tink::HybridEncrypt> *ccKeyManager = nullptr;
  if (keyManager) {
    ccKeyManager = keyManager.ccKeyManager;
  }

  auto ccHybridEncrypt = crypto::tink::HybridEncryptFactory::GetPrimitive(*ccHandle, ccKeyManager);
  if (!ccHybridEncrypt.ok()) {
    if (error) {
      *error = TINKStatusToError(ccHybridEncrypt.status());
    }
    return nil;
  }

  auto ccPrimitive = ccHybridEncrypt.ValueOrDie().release();

  // Wrap the C++ HybridEncrypt primitive into a TINKHybridEncrypt Obj-C instance.
  id<TINKHybridEncrypt> objcHybridEncrypt =
      [[TINKHybridEncryptInternal alloc] initWithPrimitive:ccPrimitive];
  if (!objcHybridEncrypt) {
    if (error) {
      *error = TINKStatusToError(
          crypto::tink::util::Status(
              crypto::tink::util::error::RESOURCE_EXHAUSTED,
              "Cannot initialize TINKHybridEncrypt"));
    }
    return nil;
  }

  return objcHybridEncrypt;
}

@end
