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

// Implementation of a server metadata service.
#include "metadata_impl.h"
#include "tink/version.h"

namespace tink_testing_api {

using ::grpc::ServerContext;
using ::grpc::Status;

// Returns server info.
grpc::Status MetadataImpl::GetServerInfo(grpc::ServerContext* context,
                                         const ServerInfoRequest* request,
                                         ServerInfoResponse* response) {
  response->set_language("cc");
  response->set_tink_version(crypto::tink::Version::kTinkVersion);
  return ::grpc::Status::OK;
}

}  // namespace tink_testing_api
