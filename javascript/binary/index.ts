/**
 * @license
 * Copyright 2020 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */

import {BinaryKeysetReader} from '../internal/binary_keyset_reader';
import {KeysetHandle, readNoSecret} from '../internal/keyset_handle';

export function deserializeNoSecretKeyset(
    serializedKeyset: Uint8Array): KeysetHandle {
  return readNoSecret(BinaryKeysetReader.withUint8Array(serializedKeyset));
}
