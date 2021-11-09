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

#ifndef TINK_PYTHON_CC_TEST_UTIL_H_
#define TINK_PYTHON_CC_TEST_UTIL_H_

#include "absl/status/status.h"
#include "tink/cc/python_file_object_adapter.h"
#include "tink/streaming_aead.h"
#include "absl/base/thread_annotations.h"
#include "absl/strings/str_cat.h"
#include "absl/synchronization/mutex.h"


namespace crypto {
namespace tink {
namespace test {

// Writable PythonFileObjectAdapter for testing.
class TestWritableObject : public PythonFileObjectAdapter {
 public:
  util::StatusOr<int> Write(absl::string_view data) override {
    buffer_ += std::string(data);
    return data.size();
  }

  util::Status Close() override { return util::OkStatus(); }

  util::StatusOr<std::string> Read(int size) override {
    return util::Status(absl::StatusCode::kUnimplemented, "not readable");
  }

  std::string* GetBuffer() { return &buffer_; }

 private:
  std::string buffer_;
};

// Readable PythonFileObjectAdapter for testing.
class TestReadableObject : public PythonFileObjectAdapter {
 public:
  explicit TestReadableObject(const std::string& data) {
    buffer_ = data;
    position_ = 0;
  }

  util::StatusOr<int> Write(absl::string_view data) override {
    return util::Status(absl::StatusCode::kUnimplemented, "not writable");
  }

  util::Status Close() override { return util::OkStatus(); }

  util::StatusOr<std::string> Read(int size) override {
    if (position_ == buffer_.size() && size > 0) {
      return util::Status(absl::StatusCode::kUnknown, "EOFError");
    }
    int actual = std::min(size, static_cast<int>(buffer_.size() - position_));
    std::string to_return = buffer_.substr(position_, actual);
    position_ += actual;
    return to_return;
  }

 private:
  std::string buffer_;
  int position_;
};

// A dummy implementation of StreamingAead-interface.  An instance of
// DummyStreamingAead can be identified by a name specified as a parameter of
// the constructor.  This name concatenated with 'associated_data' for a
// specific stream yields a header of an encrypted stream produced/consumed
// by DummyStreamingAead.
class DummyStreamingAead : public StreamingAead {
 public:
  explicit DummyStreamingAead(absl::string_view streaming_aead_name)
      : streaming_aead_name_(streaming_aead_name) {}

  crypto::tink::util::StatusOr<std::unique_ptr<crypto::tink::OutputStream>>
  NewEncryptingStream(
      std::unique_ptr<crypto::tink::OutputStream> ciphertext_destination,
      absl::string_view associated_data) override {
    return {absl::make_unique<DummyEncryptingStream>(
        std::move(ciphertext_destination),
        absl::StrCat(streaming_aead_name_, associated_data))};
  }

  crypto::tink::util::StatusOr<std::unique_ptr<crypto::tink::InputStream>>
  NewDecryptingStream(
      std::unique_ptr<crypto::tink::InputStream> ciphertext_source,
      absl::string_view associated_data) override {
    return {absl::make_unique<DummyDecryptingStream>(
        std::move(ciphertext_source),
        absl::StrCat(streaming_aead_name_, associated_data))};
  }

  crypto::tink::util::StatusOr<
      std::unique_ptr<crypto::tink::RandomAccessStream>>
  NewDecryptingRandomAccessStream(
      std::unique_ptr<crypto::tink::RandomAccessStream> ciphertext_source,
      absl::string_view associated_data) override {
    return {absl::make_unique<DummyDecryptingRandomAccessStream>(
        std::move(ciphertext_source),
        absl::StrCat(streaming_aead_name_, associated_data))};
  }

  // Upon first call to Next() writes to 'ct_dest' the specifed 'header',
  // and subsequently forwards all methods calls to the corresponding
  // methods of 'cd_dest'.
  class DummyEncryptingStream : public crypto::tink::OutputStream {
   public:
    DummyEncryptingStream(std::unique_ptr<crypto::tink::OutputStream> ct_dest,
                          absl::string_view header)
        : ct_dest_(std::move(ct_dest)), header_(header),
          after_init_(false), status_(util::OkStatus()) {}

    crypto::tink::util::StatusOr<int> Next(void** data) override {
      if (!after_init_) {  // Try to initialize.
        after_init_ = true;
        auto next_result = ct_dest_->Next(data);
        if (!next_result.ok()) {
          status_ = next_result.status();
          return status_;
        }
        if (next_result.ValueOrDie() < header_.size()) {
          status_ =
              util::Status(absl::StatusCode::kInternal, "Buffer too small");
        } else {
          memcpy(*data, header_.data(), static_cast<int>(header_.size()));
          ct_dest_->BackUp(next_result.ValueOrDie() - header_.size());
        }
      }
      if (!status_.ok()) return status_;
      return ct_dest_->Next(data);
    }

    void BackUp(int count) override {
      if (after_init_ && status_.ok()) {
        ct_dest_->BackUp(count);
      }
    }

    int64_t Position() const override {
      if (after_init_ && status_.ok()) {
        return ct_dest_->Position() - header_.size();
      } else {
        return 0;
      }
    }
    util::Status Close() override {
      if (!after_init_) {  // Call Next() to write the header to ct_dest_.
        void *buf;
        auto next_result = Next(&buf);
        if (next_result.ok()) {
          BackUp(next_result.ValueOrDie());
        } else {
          status_ = next_result.status();
          return status_;
        }
      }
      return ct_dest_->Close();
    }

   private:
    std::unique_ptr<crypto::tink::OutputStream> ct_dest_;
    std::string header_;
    bool after_init_;
    util::Status status_;
  };  // class DummyEncryptingStream

  // Upon first call to Next() tries to read from 'ct_source' a header
  // that is expected to be equal to 'expected_header'.  If this
  // header matching succeeds, all subsequent method calls are forwarded
  // to the corresponding methods of 'cd_source'.
  class DummyDecryptingStream : public crypto::tink::InputStream {
   public:
    DummyDecryptingStream(std::unique_ptr<crypto::tink::InputStream> ct_source,
                          absl::string_view expected_header)
        : ct_source_(std::move(ct_source)), exp_header_(expected_header),
          after_init_(false), status_(util::OkStatus()) {}

    crypto::tink::util::StatusOr<int> Next(const void** data) override {
      if (!after_init_) {  // Try to initialize.
        after_init_ = true;
        auto next_result = ct_source_->Next(data);
        if (!next_result.ok()) {
          status_ = next_result.status();
          if (status_.code() == absl::StatusCode::kOutOfRange) {
            status_ = util::Status(absl::StatusCode::kInvalidArgument,
                                   "Could not read header");
          }
          return status_;
        }
        if (next_result.ValueOrDie() < exp_header_.size()) {
          status_ =
              util::Status(absl::StatusCode::kInternal, "Buffer too small");
        } else if (memcmp((*data), exp_header_.data(),
                          static_cast<int>(exp_header_.size()))) {
          status_ = util::Status(absl::StatusCode::kInvalidArgument,
                                 "Corrupted header");
        }
        if (status_.ok()) {
          ct_source_->BackUp(next_result.ValueOrDie() - exp_header_.size());
        }
      }
      if (!status_.ok()) return status_;
      return ct_source_->Next(data);
    }

    void BackUp(int count) override {
      if (after_init_ && status_.ok()) {
        ct_source_->BackUp(count);
      }
    }

    int64_t Position() const override {
      if (after_init_ && status_.ok()) {
        return ct_source_->Position() - exp_header_.size();
      } else {
        return 0;
      }
    }

   private:
    std::unique_ptr<crypto::tink::InputStream> ct_source_;
    std::string exp_header_;
    bool after_init_;
    util::Status status_;
  };  // class DummyDecryptingStream

  // Upon first call to PRead() tries to read from 'ct_source' a header
  // that is expected to be equal to 'expected_header'.  If this
  // header matching succeeds, all subsequent method calls are forwarded
  // to the corresponding methods of 'cd_source'.
  class DummyDecryptingRandomAccessStream :
      public crypto::tink::RandomAccessStream {
   public:
    DummyDecryptingRandomAccessStream(
        std::unique_ptr<crypto::tink::RandomAccessStream> ct_source,
        absl::string_view expected_header)
        : ct_source_(std::move(ct_source)), exp_header_(expected_header),
          status_(util::Status(absl::StatusCode::kUnavailable,
                               "not initialized")) {}

    crypto::tink::util::Status PRead(
        int64_t position, int count,
        crypto::tink::util::Buffer* dest_buffer) override {
      {  // Initialize, if not initialized yet.
        absl::MutexLock lock(&status_mutex_);
        if (status_.code() == absl::StatusCode::kUnavailable) Initialize();
        if (!status_.ok()) return status_;
      }
      auto status = dest_buffer->set_size(0);
      if (!status.ok()) return status;
      return ct_source_->PRead(
          position + exp_header_.size(), count, dest_buffer);
    }

    util::StatusOr<int64_t> size() override {
      {  // Initialize, if not initialized yet.
        absl::MutexLock lock(&status_mutex_);
        if (status_.code() == absl::StatusCode::kUnavailable) Initialize();
        if (!status_.ok()) return status_;
      }
      auto ct_size_result = ct_source_->size();
      if (!ct_size_result.ok()) return ct_size_result.status();
      auto pt_size = ct_size_result.ValueOrDie() - exp_header_.size();
      if (pt_size >= 0) return pt_size;
      return util::Status(absl::StatusCode::kUnavailable, "size not available");
    }

   private:
    void Initialize() ABSL_EXCLUSIVE_LOCKS_REQUIRED(status_mutex_) {
      auto buf = std::move(
          util::Buffer::New(exp_header_.size()).ValueOrDie());
      status_ = ct_source_->PRead(0, exp_header_.size(), buf.get());
      if (!status_.ok() &&
          status_.code() != absl::StatusCode::kOutOfRange) return;
      if (buf->size() < exp_header_.size()) {
        status_ = util::Status(absl::StatusCode::kInvalidArgument,
                               "Could not read header");
      } else if (memcmp(buf->get_mem_block(), exp_header_.data(),
                        static_cast<int>(exp_header_.size()))) {
        status_ = util::Status(absl::StatusCode::kInvalidArgument,
                               "Corrupted header");
      }
    }

    std::unique_ptr<crypto::tink::RandomAccessStream> ct_source_;
    std::string exp_header_;
    mutable absl::Mutex status_mutex_;
    util::Status status_ ABSL_GUARDED_BY(status_mutex_);
  };  // class DummyDecryptingRandomAccessStream

 private:
  std::string streaming_aead_name_;
};  // class DummyStreamingAead
}  // namespace test
}  // namespace tink
}  // namespace crypto


#endif  // TINK_PYTHON_CC_TEST_UTIL_H_
