// Copyright 2022 Google LLC
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
#ifndef THIRD_PARTY_TINK_OBJC_PROTO_REDIRECT_HMAC_CC_PB_REDIRECT_H_
#define THIRD_PARTY_TINK_OBJC_PROTO_REDIRECT_HMAC_CC_PB_REDIRECT_H_

// We export hmac.pb.h -- this allows us to include a cc_library target from
// objc instead of a cc_proto_library target, which does not seem to work at
// the moment.
#include "proto/hmac.pb.h"

#endif  // THIRD_PARTY_TINK_OBJC_PROTO_REDIRECT_HMAC_CC_PB_REDIRECT_H_
