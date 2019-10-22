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

#ifndef TINK_UTIL_INPUT_STREAM_UTIL_H_
#define TINK_UTIL_INPUT_STREAM_UTIL_H_

#include <string>

#include "tink/input_stream.h"
#include "tink/util/statusor.h"

namespace crypto {
namespace tink {

// A utility function which reads up to num_bytes from the given input
// stream, calling Next repeatedly until either 'num_bytes' are obtained or
// the end of the stream is reached. In case not enough bytes are available,
// the bytes read are returned. Other errors are propagated. This can loop
// indefinitely (in case Next() repeatedly returns 0).
::crypto::tink::util::StatusOr<std::string> ReadAtMostFromStream(
    int num_bytes, InputStream* input_stream);

}  // namespace tink
}  // namespace crypto

#endif  // TINK_UTIL_INPUT_STREAM_UTIL_H_
