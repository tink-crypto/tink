/**
 * @license
 * Copyright 2020 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */

import {PbEncryptedKeyset, PbKeyset} from './proto';

/**
 * KeysetReader knows how to read a keyset or an encrypted keyset from some
 * source.
 *
 */
export interface KeysetReader {
  /**
   * Reads and returns a (cleartext) Keyset object from the underlying source.
   *
   */
  read(): PbKeyset;

  /**
   * Reads and returns an EncryptedKeyset from the underlying source.
   *
   */
  readEncrypted(): PbEncryptedKeyset;
}
