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

#import "objc/TINKAead.h"
#import "objc/TINKKeyTemplate.h"
#import "objc/TINKKeysetReader.h"
#import "objc/aead/TINKAeadInternal.h"
#import "objc/core/TINKKeyTemplate_Internal.h"
#import "objc/core/TINKKeysetReader_Internal.h"
#import "objc/util/TINKErrors.h"
#import "objc/util/TINKStrings.h"

#include <iosfwd>
#include <iostream>
#include <sstream>
#include <string>

#include "absl/memory/memory.h"
#include "absl/strings/string_view.h"
#include "tink/binary_keyset_reader.h"
#include "tink/binary_keyset_writer.h"
#include "tink/cleartext_keyset_handle.h"
#include "tink/keyset_handle.h"
#include "tink/util/status.h"
#include "proto/tink.pb.h"

static NSString *const kTinkService = @"com.google.crypto.tink";

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

- (instancetype)initWithNoSecretKeyset:(NSData *)keyset error:(NSError **)error {
  if (keyset == nil) {
    if (error) {
      *error = TINKStatusToError(crypto::tink::util::Status(
          crypto::tink::util::error::INVALID_ARGUMENT, "keyset must be non-nil."));
    }
    return nil;
  }

  auto st = crypto::tink::KeysetHandle::ReadNoSecret(std::string(
      reinterpret_cast<const char *>(keyset.bytes), static_cast<size_t>(keyset.length)));
  if (!st.ok()) {
    if (error) {
      *error = TINKStatusToError(st.status());
      return nil;
    }
  }

  return [self initWithCCKeysetHandle:std::move(st.ValueOrDie())];
}

- (instancetype)initWithKeysetReader:(TINKKeysetReader *)reader
                              andKey:(id<TINKAead>)aeadKey
                               error:(NSError **)error {
  if (![aeadKey isKindOfClass:[TINKAeadInternal class]]) {
    if (error) {
      *error = TINKStatusToError(crypto::tink::util::Status(
          crypto::tink::util::error::INVALID_ARGUMENT, "Invalid instance of TINKAead."));
    }
    return nil;
  }

  TINKAeadInternal *aead = aeadKey;
  crypto::tink::Aead *ccAead = [aead ccAead];
  if (!ccAead) {
    if (error) {
      *error = TINKStatusToError(crypto::tink::util::Status(
          crypto::tink::util::error::INVALID_ARGUMENT, "Failed to get C++ Aead instance."));
    }
    return nil;
  }

  @synchronized(reader) {
    if (reader.used) {
      // A reader can only be used once.
      if (error) {
        *error = TINKStatusToError(
            crypto::tink::util::Status(absl::StatusCode::kResourceExhausted,
                                       "A KeysetReader can be used only once."));
      }
      return nil;
    }
    reader.used = YES;
  }
  auto st = crypto::tink::KeysetHandle::Read(reader.ccReader, *ccAead);
  if (!st.ok()) {
    if (error) {
      *error = TINKStatusToError(st.status());
      return nil;
    }
  }

  return [self initWithCCKeysetHandle:std::move(st.ValueOrDie())];
}

- (nullable instancetype)initFromKeychainWithName:(NSString *)keysetName error:(NSError **)error {
  return [self initFromKeychainWithName:keysetName accessGroup:nil error:error];
}

- (nullable instancetype)initFromKeychainWithName:(NSString *)keysetName
                                      accessGroup:(NSString *)accessGroup
                                            error:(NSError **)error {
  if (keysetName == nil) {
    if (error) {
      *error = TINKStatusToError(crypto::tink::util::Status(
          crypto::tink::util::error::INVALID_ARGUMENT, "keysetName must be non-nil."));
    }
    return nil;
  }

  if (self = [super init]) {
    NSDictionary *getQuery = @{
      (__bridge id)kSecClass : (__bridge id)kSecClassGenericPassword,
      (__bridge id)kSecAttrAccount : keysetName,
      (__bridge id)kSecAttrService : kTinkService,
      (__bridge id)kSecReturnData : (__bridge id)kCFBooleanTrue,
    };

    if (accessGroup) {
      NSMutableDictionary *mutableGetQuery =
          [NSMutableDictionary dictionaryWithDictionary:getQuery];
      [mutableGetQuery setObject:accessGroup forKey:(__bridge id)kSecAttrAccessGroup];
      getQuery = [mutableGetQuery copy];
    }

    crypto::tink::util::error::Code errorCode = crypto::tink::util::error::OK;
    std::string errorMessage = "";
    CFTypeRef dataTypeRef = NULL;
    OSStatus status = SecItemCopyMatching((CFDictionaryRef)getQuery, &dataTypeRef);
    switch (status) {
      case errSecSuccess:
        // Success, nothing to do.
        break;
      case errSecItemNotFound:
        errorMessage = "A keyset with the given name wasn't found in the keychain.";
        errorCode = crypto::tink::util::error::NOT_FOUND;
        break;
      default:
        std::ostringstream oss;
        oss << "An error occurred while trying to retrieve the keyset from the keychain.";
        oss << " Error code: " << status;
        errorMessage = oss.str();
        errorCode = crypto::tink::util::error::UNKNOWN;
    }

    if (errorCode != crypto::tink::util::error::OK) {
      if (error) {
        *error = TINKStatusToError(crypto::tink::util::Status(errorCode, errorMessage));
      }
      return nil;
    }

    NSData *keyset = (__bridge NSData *)dataTypeRef;
    auto reader = crypto::tink::BinaryKeysetReader::New(absl::string_view(
        reinterpret_cast<const char *>(keyset.bytes), static_cast<size_t>(keyset.length)));
    if (!reader.ok()) {
      if (error) {
        *error = TINKStatusToError(reader.status());
      }
      return nil;
    }

    auto read_result = crypto::tink::CleartextKeysetHandle::Read(std::move(reader.ValueOrDie()));
    if (!read_result.ok()) {
      if (error) {
        *error = TINKStatusToError(read_result.status());
        return nil;
      }
    }

    return [self initWithCCKeysetHandle:std::move(read_result.ValueOrDie())];
  }
  return nil;
}

+ (BOOL)deleteFromKeychainWithName:(NSString *)keysetName error:(NSError **)error {
  return [self deleteFromKeychainWithName:keysetName accessGroup:nil error:error];
}

+ (BOOL)deleteFromKeychainWithName:(NSString *)keysetName
                       accessGroup:(NSString *)accessGroup
                             error:(NSError **)error {
  if (keysetName == nil) {
    if (error) {
      *error = TINKStatusToError(crypto::tink::util::Status(
          crypto::tink::util::error::INVALID_ARGUMENT, "keysetName must be non-nil."));
    }
    return NO;
  }

  NSDictionary *attributes = @{
    (__bridge id)kSecClass : (__bridge id)kSecClassGenericPassword,
    (__bridge id)kSecAttrAccount : keysetName,
    (__bridge id)kSecAttrService : kTinkService,
  };

  if (accessGroup) {
    NSMutableDictionary *mutableAttributes =
        [NSMutableDictionary dictionaryWithDictionary:attributes];
    [mutableAttributes setObject:accessGroup forKey:(__bridge id)kSecAttrAccessGroup];
    attributes = [mutableAttributes copy];
  }

  OSStatus status = SecItemDelete((CFDictionaryRef)attributes);
  if (status != errSecSuccess && status != errSecItemNotFound) {
    if (error) {
      std::ostringstream oss;
      oss << "An error occurred while trying to delete the keyset from the keychain.";
      oss << " Keychain error code: " << status;
      std::string errorMessage = oss.str();
      *error = TINKStatusToError(
          crypto::tink::util::Status(crypto::tink::util::error::UNKNOWN, errorMessage));
    }
    return NO;
  }

  return YES;
}

- (BOOL)writeToKeychainWithName:(NSString *)keysetName
                      overwrite:(BOOL)overwrite
                          error:(NSError **)error {
  return [self writeToKeychainWithName:keysetName accessGroup:nil overwrite:overwrite error:error];
}

- (BOOL)writeToKeychainWithName:(NSString *)keysetName
                    accessGroup:(NSString *)accessGroup
                      overwrite:(BOOL)overwrite
                          error:(NSError **)error {
  if (keysetName == nil) {
    if (error) {
      *error = TINKStatusToError(crypto::tink::util::Status(
          crypto::tink::util::error::INVALID_ARGUMENT, "keysetName must be non-nil."));
    }
    return NO;
  }

  auto keyset = crypto::tink::CleartextKeysetHandle::GetKeyset(*self.ccKeysetHandle);

  std::string serializedKeyset;
  if (!keyset.SerializeToString(&serializedKeyset)) {
    if (error) {
      *error = TINKStatusToError(crypto::tink::util::Status(
          crypto::tink::util::error::INTERNAL, "Could not serialize C++ KeyTemplate."));
    }
    return NO;
  }

  if (overwrite) {
    if (![TINKKeysetHandle deleteFromKeychainWithName:keysetName error:error]) {
      return NO;
    }
  }

  NSData *keysetData = TINKStringToNSData(serializedKeyset);
  NSDictionary *attributes = @{
    (__bridge id)kSecClass : (__bridge id)kSecClassGenericPassword,
    (__bridge id)kSecAttrAccount : keysetName,
    (__bridge id)kSecAttrAccessible : (__bridge id)kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
    (__bridge id)kSecAttrService : kTinkService,
    (__bridge id)kSecAttrSynchronizable : (__bridge id)kCFBooleanFalse,
    (__bridge id)kSecReturnData : (__bridge id)kCFBooleanTrue,
    (__bridge id)kSecValueData : keysetData,
  };

  if (accessGroup) {
    NSMutableDictionary *mutableAttributes =
        [NSMutableDictionary dictionaryWithDictionary:attributes];
    [mutableAttributes setObject:accessGroup forKey:(__bridge id)kSecAttrAccessGroup];
    attributes = [mutableAttributes copy];
  }

  OSStatus status = SecItemAdd((__bridge CFDictionaryRef)attributes, NULL);
  switch (status) {
    case errSecSuccess:
      return YES;
    case errSecDuplicateItem:
      if (error) {
        std::ostringstream oss;
        oss << "A keyset with the same keysetName already exists in the keychain.";
        oss << " Please delete it and try again. Keychain error code: " << status;
        std::string errorMessage = oss.str();
        *error = TINKStatusToError(
            crypto::tink::util::Status(crypto::tink::util::error::UNKNOWN, errorMessage));
      }
      return NO;
    default:
      if (error) {
        std::ostringstream oss;
        oss << "An error occurred while trying to store the keyset in the keychain.";
        oss << " Error code: " << status;
        std::string errorMessage = oss.str();
        *error = TINKStatusToError(
            crypto::tink::util::Status(crypto::tink::util::error::UNKNOWN, errorMessage));
      }
      return NO;
  }
}

- (instancetype)initWithKeyTemplate:(TINKKeyTemplate *)keyTemplate error:(NSError **)error {
  auto st = crypto::tink::KeysetHandle::GenerateNew(*(keyTemplate.ccKeyTemplate));
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

+ (nullable instancetype)publicKeysetHandleWithHandle:(TINKKeysetHandle *)aHandle
                                                error:(NSError **)error {
  crypto::tink::KeysetHandle *ccKeysetHandle = aHandle.ccKeysetHandle;
  auto status = ccKeysetHandle->GetPublicKeysetHandle();
  if (!status.ok()) {
    if (error) {
      *error = TINKStatusToError(status.status());
    }
    return nil;
  }
  return [[TINKKeysetHandle alloc] initWithCCKeysetHandle:std::move(status.ValueOrDie())];
}

- (NSData *)serializedKeysetNoSecret:(NSError **)error {
  std::stringbuf buffer;
  auto writerResult = crypto::tink::BinaryKeysetWriter::New(
      absl::make_unique<std::ostream>(&buffer));
  if (!writerResult.ok()) {
    if (error) {
      *error = TINKStatusToError(writerResult.status());
    }
    return nil;
  }
  auto writer = std::move(writerResult.ValueOrDie());
  auto writeNoSecretStatus = self.ccKeysetHandle->WriteNoSecret(writer.get());
  if (!writeNoSecretStatus.ok()) {
    if (error) {
      *error = TINKStatusToError(writeNoSecretStatus);
    }
    return nil;
  }
  return TINKStringToNSData(buffer.str());
}

@end
