/**
 * @license
 * Copyright 2020 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */

import {createKeyset} from '../testing/internal/test_utils';

import {CleartextKeysetHandle} from './cleartext_keyset_handle';
import {KeysetHandle} from './keyset_handle';

describe('cleartext keyset handle test', function() {
  it('deserialize from binary', function() {
    const keyset1 = createKeyset();
    const keysetHandle =
        CleartextKeysetHandle.deserializeFromBinary(keyset1.serializeBinary());
    const keyset2 = keysetHandle.getKeyset();
    expect(keyset2.getPrimaryKeyId()).toBe(keyset1.getPrimaryKeyId());
    expect(keyset2.getKeyList()).toEqual(keyset2.getKeyList());
  });

  it('serialize to binary', function() {
    const keyset = createKeyset();
    const keysetHandle = new KeysetHandle(keyset);

    const keysetBinary = CleartextKeysetHandle.serializeToBinary(keysetHandle);
    expect(keyset.serializeBinary()).toEqual(keysetBinary);
  });
});
