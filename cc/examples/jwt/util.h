// Copyright 2021 Google LLC
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

#ifndef TINK_EXAMPLES_JWT_UTIL_H_
#define TINK_EXAMPLES_JWT_UTIL_H_

#include <fstream>
#include <iostream>
#include <string>

#include "absl/strings/string_view.h"
#include "tink/keyset_handle.h"

// Helper functions for JWT Signature CLI

// Reads a keyset from the specified file.
// In case of errors writes a log message and aborts.
std::unique_ptr<crypto::tink::KeysetHandle> ReadKeyset(
    absl::string_view filename);

// Writes the keyset to the specified file.
// In case of errors writes a log message and aborts.
void WriteKeyset(const crypto::tink::KeysetHandle& keyset_handle,
                 absl::string_view filename);

// Reads the specified file and returns the contents as a string.
// In case of errors writes a log message and aborts.
std::string ReadFile(absl::string_view filename);

// Writes the given 'output' to the specified file.
// In case of errors writes a log message and aborts.
void WriteFile(absl::string_view output, absl::string_view filename);

#endif  // TINK_EXAMPLES_JWT_UTIL_H_
