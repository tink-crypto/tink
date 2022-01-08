/**
 * @license
 * Copyright 2020 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */

import {PbEncryptedKeyset, PbKeyset} from './proto';

/**
 * KeysetWriter knows how to write a keyset or an encrypted keyset to some
 * storage system.
 *
 */
export interface KeysetWriter {
  encodeBinary(keyset: PbKeyset|PbEncryptedKeyset): Uint8Array;
}
