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

import {KeysetReader} from './keyset_reader';
import {PbEncryptedKeyset, PbKeyset} from './proto';

/**
 * BinaryKeysetReader knows how to read a keyset or an encrypted keyset
 * serialized to binary format.
 *
 * @final
 */
export class BinaryKeysetReader implements KeysetReader {
  constructor(private readonly serializedKeyset: Uint8Array) {}

  static withUint8Array(serializedKeyset: Uint8Array): BinaryKeysetReader {
    if (!serializedKeyset) {
      throw new SecurityException('Serialized keyset has to be non-null.');
    }
    return new BinaryKeysetReader(serializedKeyset);
  }

  /** @override */
  read() {
    let keyset: PbKeyset;
    try {
      keyset = PbKeyset.deserializeBinary(this.serializedKeyset);
    } catch (e) {
      throw new SecurityException(
          'Could not parse the given serialized proto as a keyset proto.');
    }
    if (keyset.getKeyList().length === 0) {
      throw new SecurityException(
          'Could not parse the given serialized proto as a keyset proto.');
    }
    return keyset;
  }

  /** @override */
  readEncrypted(): PbEncryptedKeyset {
    throw new SecurityException('Not implemented yet.');
  }
}
