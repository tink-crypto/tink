/**
 * @license
 * Copyright 2020 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */

import {SecurityException} from '../exception/security_exception';
import {KeysetWriter} from './keyset_writer';
import {PbEncryptedKeyset, PbKeyset} from './proto';

/**
 * KeysetWriter knows how to write a keyset or an encrypted keyset.
 *
 * @final
 */
export class BinaryKeysetWriter implements KeysetWriter {
  write(keyset: PbKeyset|PbEncryptedKeyset): Uint8Array {
    if (!keyset) {
      throw new SecurityException('keyset has to be non-null.');
    }
    return keyset.serializeBinary();
  }
}
