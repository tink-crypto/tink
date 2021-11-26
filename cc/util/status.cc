// Copyright 2017 Google Inc.
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

#include <sstream>

#include "tink/util/status.h"

#include "absl/strings/str_cat.h"
#include "absl/status/status.h"

using ::std::ostream;

namespace crypto {
namespace tink {
namespace util {

#ifndef TINK_USE_ABSL_STATUS
namespace {


const Status& GetCancelled() {
  static const Status* status =
      new Status(::crypto::tink::util::error::CANCELLED, "");
  return *status;
}

const Status& GetUnknown() {
  static const Status* status =
      new Status(::crypto::tink::util::error::UNKNOWN, "");
  return *status;
}

const Status& GetOk() {
  static const Status* status = new Status;
  return *status;
}

}  // namespace
#endif

Status::Status(const ::absl::Status& status)
    : code_(absl::StatusCode::kOk) {
  if (status.ok()) return;
  code_ = status.code();
  message_ = std::string(status.message());
}

Status::operator ::absl::Status() const {
  if (ok()) return ::absl::OkStatus();
  return ::absl::Status(code_, message_);
}

Status::Status() : code_(absl::StatusCode::kOk), message_("") {
}

#ifndef TINK_USE_ABSL_STATUS
Status::Status(::crypto::tink::util::error::Code error,
               const std::string& error_message)
    : code_(static_cast<absl::StatusCode>(error)), message_(error_message) {
  if (code_ == absl::StatusCode::kOk) {
    message_.clear();
  }
}
#endif

Status::Status(absl::StatusCode code, absl::string_view error_message)
    : code_(code),
      message_(error_message) {
  if (code_ == absl::StatusCode::kOk) {
    message_.clear();
  }
}

Status& Status::operator=(const Status& other) {
  code_ = other.code_;
  message_ = other.message_;
  return *this;
}

#ifndef TINK_USE_ABSL_STATUS
const Status& Status::CANCELLED = GetCancelled();
const Status& Status::UNKNOWN = GetUnknown();
const Status& Status::OK = GetOk();
#endif

std::string Status::ToString() const {
  if (code_ == absl::StatusCode::kOk) {
    return "OK";
  }

  std::ostringstream oss;
  oss << code_ << ": " << message_;
  return oss.str();
}

#ifndef TINK_USE_ABSL_STATUS
std::string ErrorCodeString(crypto::tink::util::error::Code error) {
  switch (error) {
    case crypto::tink::util::error::OK:
      return "OK";
    case crypto::tink::util::error::CANCELLED:
      return "CANCELLED";
    case crypto::tink::util::error::UNKNOWN:
      return "UNKNOWN";
    case crypto::tink::util::error::INVALID_ARGUMENT:
      return "INVALID_ARGUMENT";
    case crypto::tink::util::error::DEADLINE_EXCEEDED:
      return "DEADLINE_EXCEEDED";
    case crypto::tink::util::error::NOT_FOUND:
      return "NOT_FOUND";
    case crypto::tink::util::error::ALREADY_EXISTS:
      return "ALREADY_EXISTS";
    case crypto::tink::util::error::PERMISSION_DENIED:
      return "PERMISSION_DENIED";
    case crypto::tink::util::error::RESOURCE_EXHAUSTED:
      return "RESOURCE_EXHAUSTED";
    case crypto::tink::util::error::FAILED_PRECONDITION:
      return "FAILED_PRECONDITION";
    case crypto::tink::util::error::ABORTED:
      return "ABORTED";
    case crypto::tink::util::error::OUT_OF_RANGE:
      return "OUT_OF_RANGE";
    case crypto::tink::util::error::UNIMPLEMENTED:
      return "UNIMPLEMENTED";
    case crypto::tink::util::error::INTERNAL:
      return "INTERNAL";
    case crypto::tink::util::error::UNAVAILABLE:
      return "UNAVAILABLE";
    case crypto::tink::util::error::DATA_LOSS:
      return "DATA_LOSS";
    case crypto::tink::util::error::UNAUTHENTICATED:
      return "UNAUTHENTICATED";
  }
  // Avoid using a "default" in the switch, so that the compiler can
  // give us a warning, but still provide a fallback here.
  return absl::StrCat(error);
}

extern ostream& operator<<(ostream& os, crypto::tink::util::error::Code code) {
  os << ErrorCodeString(code);
  return os;
}
#endif

extern ostream& operator<<(ostream& os, const Status& other) {
  os << other.ToString();
  return os;
}


}  // namespace util
}  // namespace tink
}  // namespace crypto
