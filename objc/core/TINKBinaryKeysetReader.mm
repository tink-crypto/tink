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

#import "objc/TINKBinaryKeysetReader.h"

#import "objc/TINKKeysetReader.h"
#import "objc/core/TINKKeysetReader_Internal.h"
#import "objc/util/TINKErrors.h"
#import "objc/util/TINKStrings.h"
#import "proto/Tink.pbobjc.h"

#include "absl/strings/string_view.h"
#include "tink/binary_keyset_reader.h"
#include "proto/tink.pb.h"

@implementation TINKBinaryKeysetReader

- (instancetype)initWithSerializedKeyset:(NSData *)keyset error:(NSError **)error {
  if (keyset == nil) {
    if (error) {
      *error = TINKStatusToError(crypto::tink::util::Status(
          crypto::tink::util::error::INVALID_ARGUMENT, "keyset must be non-nil."));
    }
    return nil;
  }

  if (self = [super init]) {
    auto st = crypto::tink::BinaryKeysetReader::New(absl::string_view(
        reinterpret_cast<const char *>(keyset.bytes), static_cast<size_t>(keyset.length)));
    if (!st.ok()) {
      if (error) {
        *error = TINKStatusToError(st.status());
      }
      return nil;
    }
    self.ccReader = std::move(st.ValueOrDie());
  }
  return self;
}

- (TINKPBKeyset *)readWithError:(NSError **)error {
  auto st = self.ccReader->Read();
  if (!st.ok()) {
    if (error) {
      *error = TINKStatusToError(st.status());
    }
    return nil;
  }
  std::unique_ptr<google::crypto::tink::Keyset> ccKeyset = std::move(st.ValueOrDie());

  std::string serializedKeyset;
  if (!ccKeyset.get()->SerializeToString(&serializedKeyset)) {
    if (error) {
      *error = TINKStatusToError(crypto::tink::util::Status(
          crypto::tink::util::error::INVALID_ARGUMENT, "Could not serialize message."));
    }
    return nil;
  }

  NSError *parseError = nil;
  TINKPBKeyset *keyset =
      [TINKPBKeyset parseFromData:TINKStringToNSData(serializedKeyset) error:&parseError];
  if (parseError) {
    if (error) {
      *error = parseError;
    }
    return nil;
  }

  return keyset;
}

- (TINKPBEncryptedKeyset *)readEncryptedWithError:(NSError **)error {
  auto st = self.ccReader->ReadEncrypted();
  if (!st.ok()) {
    if (error) {
      *error = TINKStatusToError(st.status());
    }
    return nil;
  }
  std::unique_ptr<google::crypto::tink::EncryptedKeyset> ccKeyset = std::move(st.ValueOrDie());

  std::string serializedKeyset;
  if (!ccKeyset.get()->SerializeToString(&serializedKeyset)) {
    if (error) {
      *error = TINKStatusToError(crypto::tink::util::Status(
          crypto::tink::util::error::INVALID_ARGUMENT, "Could not serialize message."));
    }
    return nil;
  }

  NSError *parseError = nil;
  TINKPBEncryptedKeyset *keyset =
      [TINKPBEncryptedKeyset parseFromData:TINKStringToNSData(serializedKeyset) error:&parseError];
  if (parseError) {
    if (error) {
      *error = parseError;
    }
    return nil;
  }

  return keyset;
}

@end
