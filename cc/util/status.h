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
// This code was unceremoniously lifted from the version at
// github.com/google/lmctfy with a few minor modifications mainly to reduce the
// dependencies.

#ifndef TINK_UTIL_STATUS_H_
#define TINK_UTIL_STATUS_H_

#include <ostream>
#include <string>

#include "absl/base/attributes.h"
#include "absl/status/status.h"

namespace crypto {
namespace tink {
namespace util {

namespace error {

#ifndef TINK_USE_ABSL_STATUS

// These values match the error codes in the codes.proto file of the original.
enum ABSL_DEPRECATED("Prefer using absl::StatusCode instead.") Code {
  // Not an error; returned on success
  OK = 0,

  // The operation was cancelled (typically by the caller).
  CANCELLED = 1,

  // Unknown error.
  UNKNOWN = 2,

  // Client specified an invalid argument.  Note that this differs
  // from FAILED_PRECONDITION.  INVALID_ARGUMENT indicates arguments
  // that are problematic regardless of the state of the system
  // (e.g., a malformed file name).
  INVALID_ARGUMENT = 3,

  // Deadline expired before operation could complete.
  DEADLINE_EXCEEDED = 4,

  // Some requested entity (e.g., file or directory) was not found.
  NOT_FOUND = 5,

  // Some entity that we attempted to create (e.g., file or directory)
  // already exists.
  ALREADY_EXISTS = 6,

  // The caller does not have permission to execute the specified
  // operation.
  PERMISSION_DENIED = 7,

  // Some resource has been exhausted, perhaps a per-user quota, or
  // perhaps the entire file system is out of space.
  RESOURCE_EXHAUSTED = 8,

  // Operation was rejected because the system is not in a state
  // required for the operation's execution.  For example, directory
  // to be deleted may be non-empty, an rmdir operation is applied to
  // a non-directory, etc.
  //
  // A litmus test that may help a service implementor in deciding
  // between FAILED_PRECONDITION, ABORTED, and UNAVAILABLE:
  //  (a) Use UNAVAILABLE if the client can retry just the failing call.
  //  (b) Use ABORTED if the client should retry at a higher-level
  //      (e.g., restarting a read-modify-write sequence).
  //  (c) Use FAILED_PRECONDITION if the client should not retry until
  //      the system state has been explicitly fixed.  E.g., if an "rmdir"
  //      fails because the directory is non-empty, FAILED_PRECONDITION
  //      should be returned since the client should not retry unless
  //      they have first fixed up the directory by deleting files from it.
  FAILED_PRECONDITION = 9,

  // The operation was aborted, typically due to a concurrency issue
  // like sequencer check failures, transaction aborts, etc.
  //
  // See litmus test above for deciding between FAILED_PRECONDITION,
  // ABORTED, and UNAVAILABLE.
  ABORTED = 10,

  // Operation was attempted past the valid range.  E.g., seeking or
  // reading past end of file.
  //
  // Unlike INVALID_ARGUMENT, this error indicates a problem that may
  // be fixed if the system state changes. For example, a 32-bit file
  // system will generate INVALID_ARGUMENT if asked to read at an
  // offset that is not in the range [0,2^32-1], but it will generate
  // OUT_OF_RANGE if asked to read from an offset past the current
  // file size.
  OUT_OF_RANGE = 11,

  // Operation is not implemented or not supported/enabled in this service.
  UNIMPLEMENTED = 12,

  // Internal errors.  Means some invariants expected by underlying
  // system has been broken.  If you see one of these errors,
  // something is very broken.
  INTERNAL = 13,

  // The service is currently unavailable.  This is a most likely a
  // transient condition and may be corrected by retrying with
  // a backoff.
  //
  // See litmus test above for deciding between FAILED_PRECONDITION,
  // ABORTED, and UNAVAILABLE.
  UNAVAILABLE = 14,

  // Unrecoverable data loss or corruption.
  DATA_LOSS = 15,

  // Invalid authentication credentials.
  UNAUTHENTICATED = 16,
};

#endif

}  // namespace error

// TODO(tholenst) Remove this compile time flag in Tink 1.5. This should not be
// used, except as a temporary measure.
#ifndef CPP_TINK_TEMPORARY_STATUS_MUST_NOT_USE_RESULT
class ABSL_MUST_USE_RESULT Status;
#endif

// A Status is a combination of an error code and a string message (for non-OK
// error codes).
class Status {
 public:
  // Creates an OK status
  Status();

  #ifndef TINK_USE_ABSL_STATUS
  // Make a Status from the specified error and message.
  Status(::crypto::tink::util::error::Code error,
         const std::string& error_message);
  #endif
  // Abseil-compatible constructor from an error and a message
  Status(absl::StatusCode code, absl::string_view error_message);

  Status(const Status& other) = default;

  Status& operator=(const Status& other);

  #ifndef TINK_USE_ABSL_STATUS
  // Some pre-defined Status objects
  ABSL_DEPRECATED("Use OkStatus() instead.")
  static const Status& OK;  // Identical to 0-arg constructor
  ABSL_DEPRECATED("Use Status(absl::StatusCode::kCancelled, "") instead.")
  static const Status& CANCELLED;
  ABSL_DEPRECATED("Use Status(absl::StatusCode::kUnknown, "") instead.")
  static const Status& UNKNOWN;
  #endif

  // Accessors
  bool ok() const {
    return code_ == absl::StatusCode::kOk;
  }
  #ifndef TINK_USE_ABSL_STATUS
  ABSL_DEPRECATED("Use its absl-compatible version code() instead.")
  int error_code() const {
    return static_cast<int>(code_);
  }
  ABSL_DEPRECATED("Use its absl-compatible version code() instead.")
  ::crypto::tink::util::error::Code CanonicalCode() const {
    return static_cast<::crypto::tink::util::error::Code>(code_);
  }
  #endif
  ABSL_DEPRECATED("Use its absl-compatible version message() instead.")
  const std::string& error_message() const { return message_; }

  // Abseil-compatible accessors
  absl::StatusCode code() const {
    return static_cast<absl::StatusCode>(code_);
  }
  absl::string_view message() const {
    return message_;
  }

  bool operator==(const Status& other) const;
  bool operator!=(const Status& other) const;

  // NoOp
  void IgnoreError() const {
  }

  std::string ToString() const;

  Status(const ::absl::Status& status);
  operator ::absl::Status() const;

 private:
  absl::StatusCode code_;
  std::string message_;
};

inline bool Status::operator==(const Status& other) const {
  return (this->code_ == other.code_) && (this->message_ == other.message_);
}

inline bool Status::operator!=(const Status& other) const {
  return !(*this == other);
}

#ifndef TINK_USE_ABSL_STATUS
extern std::string ErrorCodeString(crypto::tink::util::error::Code error);

extern ::std::ostream& operator<<(::std::ostream& os,
                                  ::crypto::tink::util::error::Code code);
#endif
extern ::std::ostream& operator<<(::std::ostream& os, const Status& other);

// Returns an OK status, equivalent to a default constructed instance.
inline Status OkStatus() { return Status(); }

}  // namespace util
}  // namespace tink
}  // namespace crypto

#endif  // TINK_UTIL_STATUS_H_
