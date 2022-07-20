/**
 * @license
 * Copyright 2020 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */

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

  readEncrypted(): PbEncryptedKeyset {
    throw new SecurityException('Not implemented yet.');
  }
}
