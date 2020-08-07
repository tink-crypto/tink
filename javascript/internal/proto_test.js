/**
 * @license
 * Copyright 2020 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */

goog.module('tink.ProtoTest');
goog.setTestOnly('tink.ProtoTest');

const {PbKeyset} = goog.require('google3.third_party.tink.javascript.internal.proto');

describe('proto test', function() {
  it('field', function() {
    const keyset = new PbKeyset().setPrimaryKeyId(1);
    expect(keyset.getPrimaryKeyId()).toBe(1);
  });
});
