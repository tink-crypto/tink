// Copyright 2019 Google LLC
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

#include "tink/subtle/streaming_mac_impl.h"

#include "absl/memory/memory.h"
#include "absl/status/status.h"
#include "tink/util/status.h"

namespace crypto {
namespace tink {
namespace subtle {

namespace {
constexpr size_t kBufferSize = 4096;
}

class ComputeMacOutputStream : public OutputStreamWithResult<std::string> {
 public:
  explicit ComputeMacOutputStream(std::unique_ptr<StatefulMac> mac)
      : status_(util::OkStatus()),
        mac_(std::move(mac)),
        position_(0),
        buffer_position_(0),
        buffer_("") {
    buffer_.resize(kBufferSize);
  }

  util::StatusOr<int> NextBuffer(void** buffer) override;
  util::StatusOr<std::string> CloseStreamAndComputeResult() override;
  void BackUp(int count) override;
  int64_t Position() const override { return position_; }

 private:
  void WriteIntoMac();

  util::Status status_;
  const std::unique_ptr<StatefulMac> mac_;
  int64_t position_;
  int buffer_position_;
  std::string buffer_;
};

util::StatusOr<std::unique_ptr<OutputStreamWithResult<std::string>>>
StreamingMacImpl::NewComputeMacOutputStream() const {
  util::StatusOr<std::unique_ptr<StatefulMac>> mac_status =
      mac_factory_->Create();

  if (!mac_status.ok()) {
    return mac_status.status();
  }

  std::unique_ptr<OutputStreamWithResult<std::string>> string_to_return =
      absl::make_unique<ComputeMacOutputStream>(
          std::move(mac_status.ValueOrDie()));
  return string_to_return;
}

util::StatusOr<int> ComputeMacOutputStream::NextBuffer(void** buffer) {
  if (!status_.ok()) {
    return status_;
  }
  WriteIntoMac();
  *buffer = &buffer_[0];
  position_ += kBufferSize;
  buffer_position_ = kBufferSize;
  return buffer_position_;
}

util::StatusOr<std::string>
ComputeMacOutputStream::CloseStreamAndComputeResult() {
  if (!status_.ok()) {
    return status_;
  }
  WriteIntoMac();
  status_ =
      util::Status(absl::StatusCode::kFailedPrecondition, "Stream Closed");
  return mac_->Finalize();
}

void ComputeMacOutputStream::BackUp(int count) {
  count = std::min(count, buffer_position_);
  buffer_position_ -= count;
  position_ -= count;
}

// Writes the data in buffer_ into mac_, and clears buffer_.
void ComputeMacOutputStream::WriteIntoMac() {
  // Remove the suffix of the buffer (all data after buffer_position_).
  status_ = mac_->Update(absl::string_view(buffer_.data(), buffer_position_));

  // Clear the buffer, so that any sensitive information that
  // was written to the buffer cannot be accessed later.
  // Write buffer_position_ number of 0's to the buffer, starting from idx 0.
  buffer_.replace(0, buffer_position_, buffer_position_, 0);
}

class VerifyMacOutputStream : public OutputStreamWithResult<util::Status> {
 public:
  VerifyMacOutputStream(const std::string& expected,
                        std::unique_ptr<StatefulMac> mac)
      : status_(util::OkStatus()),
        mac_(std::move(mac)),
        position_(0),
        buffer_position_(0),
        buffer_(""),
        expected_(expected) {
    buffer_.resize(kBufferSize);
  }

  util::StatusOr<int> NextBuffer(void** buffer) override;

  util::Status CloseStreamAndComputeResult() override;

  void BackUp(int count) override;
  int64_t Position() const override { return position_; }

 private:
  void WriteIntoMac();

  // Stream status: Initialized as OK, and
  // changed to ERROR:FAILED_PRECONDITION when the stream is closed.
  util::Status status_;
  std::unique_ptr<StatefulMac> mac_;
  int64_t position_;
  int buffer_position_;
  std::string buffer_;
  std::string expected_;
};

util::StatusOr<int> VerifyMacOutputStream::NextBuffer(void** buffer) {
  if (!status_.ok()) {
    return status_;
  }
  WriteIntoMac();
  *buffer = &buffer_[0];
  position_ += kBufferSize;
  buffer_position_ = kBufferSize;
  return buffer_position_;
}

util::Status VerifyMacOutputStream::CloseStreamAndComputeResult() {
  if (!status_.ok()) {
    return status_;
  }
  WriteIntoMac();
  status_ =
      util::Status(absl::StatusCode::kFailedPrecondition, "Stream Closed");
  util::StatusOr<std::string> mac_actual = mac_->Finalize();
  if (!mac_actual.ok()) {
    return mac_actual.status();
  }
  if (mac_actual.ValueOrDie() == expected_) {
    return util::OkStatus();
  }
  return util::Status(absl::StatusCode::kInvalidArgument, "Incorrect MAC");
}

void VerifyMacOutputStream::BackUp(int count) {
  count = std::min(count, buffer_position_);
  buffer_position_ -= count;
  position_ -= count;
}

// Writes the data in buffer_ into mac_, and clears buffer_.
void VerifyMacOutputStream::WriteIntoMac() {
  // Remove the suffix of the buffer (all data after buffer_position_).
  status_ = mac_->Update(absl::string_view(buffer_.data(), buffer_position_));

  // Clear the buffer, so that any sensitive information that
  // was written to the buffer cannot be accessed later.
  // Write buffer_position_ number of 0's to the buffer, starting from idx 0.
  buffer_.replace(0, buffer_position_, buffer_position_, 0);
}

util::StatusOr<std::unique_ptr<OutputStreamWithResult<util::Status>>>
StreamingMacImpl::NewVerifyMacOutputStream(const std::string& mac_value) const {
  util::StatusOr<std::unique_ptr<StatefulMac>> mac_status =
      mac_factory_->Create();
  if (!mac_status.ok()) {
    return mac_status.status();
  }
  return std::unique_ptr<OutputStreamWithResult<util::Status>>(
      absl::make_unique<VerifyMacOutputStream>(
          mac_value, std::move(mac_status.ValueOrDie())));
}
}  // namespace subtle
}  // namespace tink
}  // namespace crypto
