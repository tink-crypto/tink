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

#import "objc/hybrid/TINKEciesAeadHkdfPublicKeyManager.h"

#include "cc/hybrid/ecies_aead_hkdf_public_key_manager.h"
#include "cc/hybrid_encrypt.h"
#include "cc/key_manager.h"
#include "cc/util/status.h"
#include "proto/ecies_aead_hkdf.pb.h"
#include "proto/tink.pb.h"

#import "objc/hybrid/TINKHybridEncryptInternal.h"
#import "objc/hybrid/TINKHybridEncryptKeyManager.h"
#import "objc/hybrid/TINKHybridEncryptKeyManager_Internal.h"
#import "objc/util/TINKErrors.h"
#import "objc/util/TINKStrings.h"
#import "proto/EciesAeadHkdf.pbobjc.h"
#import "proto/Tink.pbobjc.h"

@implementation TINKEciesAeadHkdfPublicKeyManager

- (instancetype)init {
  self = [super init];
  if (self) {
    self.ccKeyManager = new crypto::tink::EciesAeadHkdfPublicKeyManager();
    self.isManagerOwnedByRegistry = NO;
  }
  return self;
}

- (void)dealloc {
  if (!self.isManagerOwnedByRegistry) {
    delete self.ccKeyManager;
  }
}

- (NSUInteger)version {
  return self.ccKeyManager->get_version();
}

- (NSString *)keyType {
  return TINKStringToNSString(self.ccKeyManager->get_key_type());
}

- (BOOL)shouldSupportKeyType:(NSString *)keyType {
  return [keyType isEqualToString:self.keyType];
}

- (id<TINKHybridEncrypt>)primitiveFromKeyData:(TINKPBKeyData *)keyData error:(NSError **)error {
  if (error) {
    *error = nil;
  }

  // Serialize the Obj-C protocol buffer.
  std::string serializedKeyData = TINKPBSerializeToString(keyData, error);
  if (serializedKeyData.empty()) {
    return nil;
  }

  // Deserialize it to a C++ protocol buffer.
  google::crypto::tink::KeyData ccKeyData;
  if (!ccKeyData.ParseFromString(serializedKeyData)) {
    if (error) {
      *error = TINKStatusToError(crypto::tink::util::Status(
          crypto::tink::util::error::INVALID_ARGUMENT, "Could not parse keyData."));
    }
    return nil;
  }

  // Use the C++ API to get a primitive from the C++ protcol buffer.
  auto st = self.ccKeyManager->GetPrimitive(ccKeyData);
  if (!st.ok()) {
    if (error) {
      *error = TINKStatusToError(st.status());
    }
    return nil;
  }

  // Wrap the C++ primitive into an Obj-C class and return it to the user.
  auto ccPrimitive = st.ValueOrDie().release();
  id<TINKHybridEncrypt> primitive =
      [[TINKHybridEncryptInternal alloc] initWithPrimitive:ccPrimitive];
  return primitive;
}

- (nullable id<TINKHybridEncrypt>)primitiveFromKey:(TINKPBEciesAeadHkdfPublicKey *)key
                                             error:(NSError **)error {
  if (error) {
    *error = nil;
  }

  // Serialize the Obj-C protocol buffer.
  std::string serializedKey = TINKPBSerializeToString(key, error);
  if (serializedKey.empty()) {
    return nil;
  }

  // Deserialize it to a C++ protocol buffer.
  google::crypto::tink::EciesAeadHkdfPublicKey ccKey;
  if (!ccKey.ParseFromString(serializedKey)) {
    if (error) {
      *error = TINKStatusToError(crypto::tink::util::Status(
          crypto::tink::util::error::INVALID_ARGUMENT, "Could not parse key."));
    }
    return nil;
  }

  // Use the C++ API to get a primitive.
  auto st = self.ccKeyManager->GetPrimitive(ccKey);
  if (!st.ok()) {
    if (error) {
      *error = TINKStatusToError(st.status());
    }
    return nil;
  }

  // Wrap the C++ primitive into an Obj-C class and return it to the user.
  auto ccPrimitive = st.ValueOrDie().release();
  id<TINKHybridEncrypt> primitive =
      [[TINKHybridEncryptInternal alloc] initWithPrimitive:ccPrimitive];
  return primitive;
}

- (nullable TINKPBEciesAeadHkdfPublicKey *)newKeyFromTemplate:(TINKPBKeyTemplate *)keyTemplate
                                                        error:(NSError **)error {
  if (error) {
    *error = nil;
  }

  // Serialize the Obj-C protocol buffer.
  std::string serializedKeyTemplate = TINKPBSerializeToString(keyTemplate, error);
  if (serializedKeyTemplate.empty()) {
    return nil;
  }

  // Deserialize it to a C++ protcol buffer.
  google::crypto::tink::KeyTemplate ccKeyTemplate;
  if (!ccKeyTemplate.ParseFromString(serializedKeyTemplate)) {
    if (error) {
      *error = TINKStatusToError(crypto::tink::util::Status(
          crypto::tink::util::error::INVALID_ARGUMENT, "Could not parse keyTemplate."));
    }
    return nil;
  }

  // Call the C++ API to get the key.
  auto st = self.ccKeyManager->get_key_factory().NewKey(ccKeyTemplate);
  if (!st.ok()) {
    if (error) {
      *error = TINKStatusToError(st.status());
    }
    return nil;
  }

  // Serialize C++ EciesAeadHkdfPublicKey to std::string.
  auto ccEciesAeadHkdfPublicKey = std::move(st.ValueOrDie());
  std::string serializedEciesAeadHkdfPublicKey;
  if (!ccEciesAeadHkdfPublicKey->SerializeToString(&serializedEciesAeadHkdfPublicKey)) {
    if (error) {
      *error = TINKStatusToError(
          crypto::tink::util::Status(crypto::tink::util::error::INVALID_ARGUMENT,
                                     "Could not serialize EciesAeadHkdfPublicKey."));
    }
    return nil;
  }

  // Deserialize to TINKPBEciesAeadHkdfPublicKey and return to user.
  TINKPBEciesAeadHkdfPublicKey *eciesAeadHkdfPublicKey = [TINKPBEciesAeadHkdfPublicKey
      parseFromData:TINKStringToNSData(serializedEciesAeadHkdfPublicKey)
              error:error];
  return eciesAeadHkdfPublicKey;
}

@end
