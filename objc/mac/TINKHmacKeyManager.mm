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

#import "objc/mac/TINKHmacKeyManager.h"

#import "GPBProtocolBuffers.h"
#import "objc/TINKMac.h"
#import "objc/mac/TINKMacInternal.h"
#import "objc/mac/TINKMacKeyManager.h"
#import "objc/mac/TINKMacKeyManager_Internal.h"
#import "objc/util/TINKErrors.h"
#import "objc/util/TINKStrings.h"
#import "proto/Hmac.pbobjc.h"
#import "proto/Tink.pbobjc.h"

#include "cc/mac/hmac_key_manager.h"
#include "cc/util/status.h"
#include "google/protobuf/message.h"
#include "proto/hmac.pb.h"
#include "proto/tink.pb.h"

@implementation TINKHmacKeyManager

- (instancetype)init {
  self = [super init];
  if (self) {
    self.ccKeyManager = new crypto::tink::HmacKeyManager();
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

- (id<TINKMac>)primitiveFromKeyData:(TINKPBKeyData *)keyData error:(NSError **)error {
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
  id<TINKMac> primitive = [[TINKMacInternal alloc] initWithPrimitive:ccPrimitive];
  return primitive;
}

- (id<TINKMac>)primitiveFromKey:(TINKPBHmacKey *)key error:(NSError **)error {
  if (error) {
    *error = nil;
  }

  // Serialize the Obj-C protocol buffer.
  std::string serializedKey = TINKPBSerializeToString(key, error);
  if (serializedKey.empty()) {
    return nil;
  }

  // Deserialize it to a C++ protocol buffer.
  google::crypto::tink::HmacKey ccKey;
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
  id<TINKMac> primitive = [[TINKMacInternal alloc] initWithPrimitive:ccPrimitive];
  return primitive;
}

- (TINKPBHmacKey *)newKeyFromTemplate:(TINKPBKeyTemplate *)keyTemplate error:(NSError **)error {
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

  // Serialize C++ HmacKey to std::string.
  auto ccHmacKey = std::move(st.ValueOrDie());
  std::string serializedHmacKey;
  if (!ccHmacKey->SerializeToString(&serializedHmacKey)) {
    if (error) {
      *error = TINKStatusToError(crypto::tink::util::Status(
          crypto::tink::util::error::INVALID_ARGUMENT, "Could not serialize hmacKey."));
    }
    return nil;
  }

  // Deserialize to TINKPBHmacKey and return to user.
  TINKPBHmacKey *hmacKey =
      [TINKPBHmacKey parseFromData:TINKStringToNSData(serializedHmacKey) error:error];
  return hmacKey;
}

@end
