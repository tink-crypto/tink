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

#ifndef TOOLS_TESTING_CC_CLI_UTIL_H_
#define TOOLS_TESTING_CC_CLI_UTIL_H_

#include <fstream>
#include <iostream>
#include <string>

#include "tink/input_stream.h"
#include "tink/keyset_handle.h"
#include "tink/output_stream.h"

// Helper function for CLI applications.
class CliUtil {
 public:
  // Returns a BinaryKeysetReader that reads from the specified file.
  // In case of errors writes a log message and aborts.
  static std::unique_ptr<crypto::tink::KeysetReader> GetBinaryKeysetReader(
      const std::string& filename);

  // Returns a JsonKeysetReader that reads from the specified file.
  // In case of errors writes a log message and aborts.
  static std::unique_ptr<crypto::tink::KeysetReader> GetJsonKeysetReader(
      const std::string& filename);

  // Returns a BinaryKeysetWriter that writes from the specified file.
  // In case of errors writes a log message and aborts.
  static std::unique_ptr<crypto::tink::KeysetWriter> GetBinaryKeysetWriter(
      const std::string& filename);

  // Returns a JsonKeysetWriter that writes from the specified file.
  // In case of errors writes a log message and aborts.
  static std::unique_ptr<crypto::tink::KeysetWriter> GetJsonKeysetWriter(
      const std::string& filename);

  // Reads a keyset from the specified file.
  // In case of errors writes a log message and aborts.
  static std::unique_ptr<crypto::tink::KeysetHandle> ReadKeyset(
      const std::string& filename);

  // Writes a keyset into the specified file.
  // In case of errors writes a log message and aborts.
  static void WriteKeyset(const crypto::tink::KeysetHandle& keyset_handle,
                          const std::string& filename);

  // Initializes Tink registry.
  // In case of errors writes a log message and aborts.
  static void InitTink();

  // Initializes a GCP client.
  static crypto::tink::util::Status InitGcp();

  // Initializes an AWS client.
  static crypto::tink::util::Status InitAws();

  // Reads the specified file and returns the contents as a string.
  // In case of errors writes a log message and aborts.
  static std::string Read(const std::string& filename);

  // Writes the given 'output' to the specified file.
  // In case of errors writes a log message and aborts.
  static void Write(const std::string& output, const std::string& filename);

  // Reads all bytes from the specified 'input_stream', and writes them
  // into 'output_stream', where both 'input_stream' and 'output_stream'
  // must be non-null.  Afte writing all the bytes, closes 'output_stream'.
  // In case of errors writes a log message and aborts.
  static void CopyStream(crypto::tink::InputStream* input_stream,
                         crypto::tink::OutputStream* output_stream);
};

#endif  // TOOLS_TESTING_CC_CLI_UTIL_H_
