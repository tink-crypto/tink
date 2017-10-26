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

#import "objc/aead/TINKAeadFactory.h"

#import <Foundation/Foundation.h>

#import "objc/TINKAead.h"
#import "objc/TINKAead_Internal.h"
#import "objc/TINKKeysetHandle.h"
#import "objc/core/TINKKeysetHandle_Internal.h"
#import "objc/util/TINKErrors.h"

#include "cc/aead/aead_factory.h"
#include "cc/keyset_handle.h"
#include "cc/util/status.h"
#include "proto/tink.pb.h"

using namespace crypto::tink;

@implementation TINKAeadFactory

+ (TINKAead *)primitiveWithKeysetHandle:(TINKKeysetHandle *)keysetHandle error:(NSError **)error {
  *error = nil;
  KeysetHandle *handle = [keysetHandle ccKeysetHandle];

  auto aead = AeadFactory::GetPrimitive(*handle);
  if (!aead.ok()) {
    *error = TINKStatusToError(aead.status());
    return nil;
  }

  auto primitive = aead.ValueOrDie().release();
  TINKAead *tnkAead = [[TINKAead alloc] initWithPrimitive:primitive];
  if (!tnkAead) {
    *error = TINKStatusToError(crypto::tink::util::Status(
        crypto::tink::util::error::RESOURCE_EXHAUSTED, "Cannot initialize TINKAead"));
    return nil;
  }

  return tnkAead;
}

@end
