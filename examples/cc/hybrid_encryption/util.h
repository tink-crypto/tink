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

#ifndef EXAMPLES_CC_HYBRID_ENCRYPTION_UTIL_H_
#define EXAMPLES_CC_HYBRID_ENCRYPTION_UTIL_H_

#include <fstream>
#include <iostream>

#include "tink/keyset_handle.h"

// Helper functions for Digital Signatures CLI
class Util {
 public:
  // Returns a BinaryKeysetReader that reads from the specified file.
  // In case of errors writes a log message and aborts.
  static std::unique_ptr<crypto::tink::KeysetReader> GetBinaryKeysetReader(
      const std::string& filename);

  // Returns a BinaryKeysetWriter that writes from the specified file.
  // In case of errors writes a log message and aborts.
  static std::unique_ptr<crypto::tink::KeysetWriter> GetBinaryKeysetWriter(
      const std::string& filename);

  // Reads a keyset from the specified file.
  // In case of errors writes a log message and aborts.
  static std::unique_ptr<crypto::tink::KeysetHandle> ReadKeyset(
      const std::string& filename);

  // Writes the keyset to the specified file.
  // In case of errors writes a log message and aborts.
  static void WriteKeyset(
      const std::unique_ptr<crypto::tink::KeysetHandle>& keyset_handle,
      const std::string& filename);

  // Initializes Tink registry.
  // In case of errors writes a log message and aborts.
  static void InitTink();

  // Reads the specified file and returns the contents as a string.
  // In case of errors writes a log message and aborts.
  static std::string Read(const std::string& filename);

  // Writes the given 'output' to the specified file.
  // In case of errors writes a log message and aborts.
  static void Write(const std::string& output, const std::string& filename);
};

#endif  // EXAMPLES_CC_HYBRID_ENCRYPTION_UTIL_H_
