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

#import "objc/TINKAeadKeyTemplate.h"

#import "objc/TINKKeyTemplate.h"
#import "objc/core/TINKKeyTemplate_Internal.h"
#import "objc/util/TINKErrors.h"

#include "absl/status/status.h"
#include "tink/aead/aead_key_templates.h"
#include "tink/util/status.h"
#include "proto/tink.pb.h"

@implementation TINKAeadKeyTemplate

- (nullable instancetype)initWithKeyTemplate:(TINKAeadKeyTemplates)keyTemplate
                                       error:(NSError **)error {
  google::crypto::tink::KeyTemplate *ccKeyTemplate = NULL;
  switch (keyTemplate) {
    case TINKAes128Gcm:
      ccKeyTemplate = const_cast<google::crypto::tink::KeyTemplate *>(
          &crypto::tink::AeadKeyTemplates::Aes128Gcm());
      break;
    case TINKAes256Gcm:
      ccKeyTemplate = const_cast<google::crypto::tink::KeyTemplate *>(
          &crypto::tink::AeadKeyTemplates::Aes256Gcm());
      break;
    case TINKAes128CtrHmacSha256:
      ccKeyTemplate = const_cast<google::crypto::tink::KeyTemplate *>(
          &crypto::tink::AeadKeyTemplates::Aes128CtrHmacSha256());
      break;
    case TINKAes256CtrHmacSha256:
      ccKeyTemplate = const_cast<google::crypto::tink::KeyTemplate *>(
          &crypto::tink::AeadKeyTemplates::Aes256CtrHmacSha256());
      break;
    case TINKAes128Eax:
      ccKeyTemplate = const_cast<google::crypto::tink::KeyTemplate *>(
          &crypto::tink::AeadKeyTemplates::Aes128Eax());
      break;
    case TINKAes256Eax:
      ccKeyTemplate = const_cast<google::crypto::tink::KeyTemplate *>(
          &crypto::tink::AeadKeyTemplates::Aes256Eax());
      break;
    case TINKXChaCha20Poly1305:
      ccKeyTemplate = const_cast<google::crypto::tink::KeyTemplate *>(
          &crypto::tink::AeadKeyTemplates::XChaCha20Poly1305());
      break;
    default:
      if (error) {
        *error = TINKStatusToError(crypto::tink::util::Status(
            absl::StatusCode::kInvalidArgument, "Invalid TINKAeadKeyTemplate"));
      }
      return nil;
  }
  return (self = [super initWithCcKeyTemplate:ccKeyTemplate]);
}

@end
