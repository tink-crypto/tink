/**
 * @license
 * Copyright 2020 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */

goog.module('tink.BinaryKeysetWriterTest');
goog.setTestOnly('tink.BinaryKeysetWriterTest');

const {BinaryKeysetReader} = goog.require('google3.third_party.tink.javascript.internal.binary_keyset_reader');
const {BinaryKeysetWriter} = goog.require('google3.third_party.tink.javascript.internal.binary_keyset_writer');
const {createKeyset} = goog.require('google3.third_party.tink.javascript.testing.internal.test_utils');

describe('binary keyset writer test', function() {
  it('get serialized key set', function() {
    const dummyKeyset = createKeyset();

    // Write the keyset.
    const writer = new BinaryKeysetWriter();
    const serializedKeyset = writer.write(dummyKeyset);

    // Read the keyset proto serialization.
    const reader = BinaryKeysetReader.withUint8Array(serializedKeyset);
    const keysetFromReader = reader.read();

    // Test that it returns the same object as was created.
    expect(keysetFromReader).toEqual(dummyKeyset);
  });
});
