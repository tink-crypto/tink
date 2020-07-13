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
import {SecurityException} from '../exception/security_exception';
import {KeysetWriter} from './keyset_writer';
import {PbEncryptedKeyset, PbKeyset} from './proto';

/**
 * KeysetWriter knows how to write a keyset or an encrypted keyset.
 *
 * @final
 */
export class BinaryKeysetWriter implements KeysetWriter {
  /** @override */
  write(keyset: PbKeyset|PbEncryptedKeyset): Uint8Array {
    if (!keyset) {
      throw new SecurityException('keyset has to be non-null.');
    }
    return keyset.serializeBinary();
  }
}
