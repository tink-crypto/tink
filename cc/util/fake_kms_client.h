// Copyright 2020 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
///////////////////////////////////////////////////////////////////////////////

#ifndef TINK_UTIL_FAKE_KMS_CLIENT_H_
#define TINK_UTIL_FAKE_KMS_CLIENT_H_

#include <memory>

#include "absl/strings/string_view.h"
#include "tink/aead.h"
#include "tink/keyset_handle.h"
#include "tink/kms_client.h"
#include "tink/kms_clients.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"

namespace crypto {
namespace tink {
namespace test {

// FakeKmsClient is a fake implementation of KmsClient.
//
// Normally, the 'key_uri' identifies a key that is stored remotely by the KMS,
// and every operation is executed remotely using a RPC call to the KMS, since
// the key should not be sent to the client.
// In this fake implementation we want to avoid these RPC calls. We achieve this
// by encoding the key in the 'key_uri'. So the client simply needs to decode
// the key and generate an AEAD out of it. This is of course insecure and should
// only be used in testing.
class FakeKmsClient : public crypto::tink::KmsClient {
 public:
  // Creates a new FakeKmsClient that is bound to the key specified in
  // 'key_uri'.
  //
  // Either of arguments can be empty.
  // If 'key_uri' is empty, then the client is not bound to any particular key.
  // credentials_path is ignored at the moment.
  static crypto::tink::util::StatusOr<std::unique_ptr<FakeKmsClient>> New(
      absl::string_view key_uri, absl::string_view credentials_path);

  // Creates a new client and registers it in KMSClients.
  static crypto::tink::util::Status RegisterNewClient(
      absl::string_view key_uri, absl::string_view credentials_path);

  // Returns a new, random fake key_uri.
  static crypto::tink::util::StatusOr<std::string> CreateFakeKeyUri();

  // Returns true iff this client does support KMS key specified by 'key_uri'.
  bool DoesSupport(absl::string_view key_uri) const override;

  // Returns an Aead-primitive backed by KMS key specified by 'key_uri',
  // provided that this KmsClient does support 'key_uri'.
  crypto::tink::util::StatusOr<std::unique_ptr<Aead>>
  GetAead(absl::string_view key_uri) const override;

 private:
  FakeKmsClient() {}
  std::string encoded_keyset_;
};

}  // namespace test
}  // namespace tink
}  // namespace crypto

#endif  // TINK_UTIL_FAKE_KMS_CLIENT_H_
