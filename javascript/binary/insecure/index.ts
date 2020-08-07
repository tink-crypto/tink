/**
 * @license
 * Copyright 2020 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */

import {CleartextKeysetHandle} from '../../internal/cleartext_keyset_handle';

export const deserializeKeyset = CleartextKeysetHandle.deserializeFromBinary;
export const serializeKeyset = CleartextKeysetHandle.serializeToBinary;
