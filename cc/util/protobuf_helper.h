// Copyright 2018 Google Inc.
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

#ifndef TINK_UTIL_PROTOBUF_HELPER_H_
#define TINK_UTIL_PROTOBUF_HELPER_H_

// copybara:replace_start
// Keep synchronized with google3/third_party/tink/copybara/cc.bara.sky
#ifdef PROTOBUF_INTERNAL_IMPL

#include "net/proto2/public/message.h"

namespace portable_proto = ::proto2;

#else
// copybara:replace_end

#include "google/protobuf/message.h"

namespace portable_proto = ::google::protobuf;

#endif  // PROTOBUF_INTERNAL_IMP

#endif  // TINK_UTIL_PROTOBUF_HELPER_H_
