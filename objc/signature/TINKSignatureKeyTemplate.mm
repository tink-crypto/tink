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

#import "objc/TINKSignatureKeyTemplate.h"

#import "objc/TINKKeyTemplate.h"
#import "objc/core/TINKKeyTemplate_Internal.h"
#import "objc/util/TINKErrors.h"

#include "absl/status/status.h"
#include "tink/signature/signature_key_templates.h"
#include "tink/util/status.h"
#include "proto/tink.pb.h"

@implementation TINKSignatureKeyTemplate

- (nullable instancetype)initWithKeyTemplate:(TINKSignatureKeyTemplates)keyTemplate
                                       error:(NSError **)error {
  google::crypto::tink::KeyTemplate *ccKeyTemplate = NULL;
  switch (keyTemplate) {
    case TINKEcdsaP256:
      ccKeyTemplate = const_cast<google::crypto::tink::KeyTemplate *>(
          &crypto::tink::SignatureKeyTemplates::EcdsaP256());
      break;
    case TINKEcdsaP384:
      ccKeyTemplate = const_cast<google::crypto::tink::KeyTemplate *>(
          &crypto::tink::SignatureKeyTemplates::EcdsaP384Sha512());
      break;
    case TINKEcdsaP521:
      ccKeyTemplate = const_cast<google::crypto::tink::KeyTemplate *>(
          &crypto::tink::SignatureKeyTemplates::EcdsaP521());
      break;
    case TINKEcdsaP256Ieee:
      ccKeyTemplate = const_cast<google::crypto::tink::KeyTemplate *>(
          &crypto::tink::SignatureKeyTemplates::EcdsaP256Ieee());
      break;
    case TINKEcdsaP384Ieee:
      ccKeyTemplate = const_cast<google::crypto::tink::KeyTemplate *>(
          &crypto::tink::SignatureKeyTemplates::EcdsaP384Ieee());
      break;
    case TINKEcdsaP521Ieee:
      ccKeyTemplate = const_cast<google::crypto::tink::KeyTemplate *>(
          &crypto::tink::SignatureKeyTemplates::EcdsaP521Ieee());
      break;
    case TINKRsaSsaPkcs13072Sha256F4:
      ccKeyTemplate = const_cast<google::crypto::tink::KeyTemplate *>(
          &crypto::tink::SignatureKeyTemplates::RsaSsaPkcs13072Sha256F4());
      break;
    case TINKRsaSsaPkcs14096Sha512F4:
      ccKeyTemplate = const_cast<google::crypto::tink::KeyTemplate *>(
          &crypto::tink::SignatureKeyTemplates::RsaSsaPkcs14096Sha512F4());
      break;
    case TINKRsaSsaPss3072Sha256Sha256F4:
      ccKeyTemplate = const_cast<google::crypto::tink::KeyTemplate *>(
          &crypto::tink::SignatureKeyTemplates::RsaSsaPss3072Sha256Sha256F4());
      break;
    case TINKRsaSsaPss4096Sha512Sha512F4:
      ccKeyTemplate = const_cast<google::crypto::tink::KeyTemplate *>(
          &crypto::tink::SignatureKeyTemplates::RsaSsaPss4096Sha512Sha512F4());
      break;
    case TINKEd25519:
      ccKeyTemplate = const_cast<google::crypto::tink::KeyTemplate *>(
          &crypto::tink::SignatureKeyTemplates::Ed25519());
      break;
    case TINKEcdsaP384Sha384:
      ccKeyTemplate = const_cast<google::crypto::tink::KeyTemplate *>(
          &crypto::tink::SignatureKeyTemplates::EcdsaP384Sha384());
      break;
    case TINKEcdsaP384Sha512:
      ccKeyTemplate = const_cast<google::crypto::tink::KeyTemplate *>(
          &crypto::tink::SignatureKeyTemplates::EcdsaP384Sha512());
      break;
    default:
      if (error) {
        *error = TINKStatusToError(crypto::tink::util::Status(
            absl::StatusCode::kInvalidArgument, "Invalid TINKSignatureKeyTemplate"));
      }
      return nil;
  }
  return (self = [super initWithCcKeyTemplate:ccKeyTemplate]);
}

@end
