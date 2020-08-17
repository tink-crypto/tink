/**
 * @license
 * Copyright 2020 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */

import 'jasmine';

import {createKeyset} from '../testing/internal/test_utils';

import {CleartextKeysetHandle} from './cleartext_keyset_handle';
import {KeysetHandle} from './keyset_handle';
import {PbKeyset} from './proto';

describe('cleartext keyset handle test', function() {
  it('parse from lightweight should work', function() {
    expect(
        CleartextKeysetHandle.fromJspbArray(createKeyset().toArray()) instanceof
        KeysetHandle)
        .toBe(true);
  });

  it('parse from lightweight empty keyset', function() {
    const keysetJspbArray = new PbKeyset().toArray();
    expect(() => {
      CleartextKeysetHandle.fromJspbArray(keysetJspbArray);
    })
        .toThrowError(
            'Keyset should be non null and must contain at least one key.');
  });

  it('deserialize from jspb', function() {
    const keyset1 = createKeyset();
    const keysetHandle =
        CleartextKeysetHandle.deserializeFromJspb(keyset1.serialize());
    const keyset2 = keysetHandle.getKeyset();
    expect(keyset2.getPrimaryKeyId()).toBe(keyset1.getPrimaryKeyId());
    expect(keyset2.getKeyList()).toEqual(keyset2.getKeyList());
  });

  it('serialize to jspb', function() {
    const keyset = createKeyset();
    const keysetHandle = new KeysetHandle(keyset);

    const keysetString = CleartextKeysetHandle.serializeToJspb(keysetHandle);
    expect(keyset.serialize()).toBe(keysetString);
  });

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
