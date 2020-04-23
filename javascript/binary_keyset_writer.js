// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
////////////////////////////////////////////////////////////////////////////////

goog.module('tink.BinaryKeysetWriter');

const KeysetWriter = goog.require('tink.KeysetWriter');
const {SecurityException} = goog.require('google3.third_party.tink.javascript.exception.security_exception');


/**
 * KeysetWriter knows how to write a keyset or an encrypted keyset.
 *
 * @implements {KeysetWriter}
 * @final
 */
class BinaryKeysetWriter {
  /** @override */
  write(keyset) {
    if (!keyset) {
      throw new SecurityException('keyset has to be non-null.');
    }
    return keyset.serializeBinary();
  }
}

exports = BinaryKeysetWriter;
