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

// Implementation of a Keyset Service.
#include "keyset_impl.h"

#include "tink/binary_keyset_writer.h"
#include "tink/cleartext_keyset_handle.h"
#include "tink/keyset_handle.h"
#include "proto/tink.pb.h"

namespace tink_testing_api {

using ::crypto::tink::BinaryKeysetWriter;
using ::crypto::tink::CleartextKeysetHandle;
using ::crypto::tink::KeysetHandle;
using ::google::crypto::tink::KeyTemplate;
using ::grpc::ServerContext;
using ::grpc::Status;

KeysetImpl::KeysetImpl() {}

// Generates a new keyset with one key from a template.
::grpc::Status KeysetImpl::Generate(grpc::ServerContext* context,
                                    const KeysetGenerateRequest* request,
                                    KeysetGenerateResponse* response) {
  KeyTemplate key_template;
  if (!key_template.ParseFromString(request->template_())) {
    response->set_err("Could not parse the key template");
    return ::grpc::Status::OK;
  }
  auto handle_result = KeysetHandle::GenerateNew(key_template);
  if (!handle_result.ok()) {
    response->set_err(handle_result.status().error_message());
    return ::grpc::Status::OK;
  }
  std::stringbuf keyset;
  auto writer_result =
      BinaryKeysetWriter::New(absl::make_unique<std::ostream>(&keyset));
  if (!writer_result.ok()) {
    response->set_err(writer_result.status().error_message());
    return ::grpc::Status::OK;
  }
  auto status = CleartextKeysetHandle::Write(writer_result.ValueOrDie().get(),
                                             *handle_result.ValueOrDie());
  if (!status.ok()) {
    response->set_err(status.error_message());
    return ::grpc::Status::OK;
  }
  response->set_keyset(keyset.str());
  return ::grpc::Status::OK;
}

}  // namespace tink_testing_api
