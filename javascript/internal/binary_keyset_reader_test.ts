/**
 * @license
 * Copyright 2020 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */

import * as Random from '../subtle/random';
import {assertMessageEquals} from '../testing/internal/test_utils';

import {BinaryKeysetReader} from './binary_keyset_reader';
import {PbKeyData, PbKeyset, PbKeysetKey, PbKeyStatusType, PbOutputPrefixType} from './proto';

describe('binary keyset reader test', function() {
  it('read, invalid serialized keyset proto', function() {
    for (let i = 0; i < 2; i++) {
      // The Uint8Array is not a serialized keyset.
      const reader = BinaryKeysetReader.withUint8Array(new Uint8Array(i));

      try {
        reader.read();
        fail('An exception should be thrown.');
      } catch (e: any) {
        expect(e.toString()).toBe(ExceptionText.invalidSerialization());
      }
    }
  });

  it('read', function() {
    // Create keyset proto and serialize it.
    const keyset = new PbKeyset();
    // The for cycle starts from 1 as setting any proto value to 0 sets it to
    // null and after serialization and deserialization null is changed to
    // undefined and the assertion at the end fails (unless you compare the
    // keyset and newly created keyset value by value).
    for (let i = 1; i < 20; i++) {
      let outputPrefix;
      switch (i % 3) {
        case 0:
          outputPrefix = PbOutputPrefixType.TINK;
          break;
        case 1:
          outputPrefix = PbOutputPrefixType.RAW;
          break;
        default:
          outputPrefix = PbOutputPrefixType.LEGACY;
      }
      keyset.addKey(createDummyKeysetKey(
          /* keyId = */ i, outputPrefix, /* enabled = */ i % 4 < 3));
    }
    keyset.setPrimaryKeyId(1);

    const serializedKeyset = keyset.serializeBinary();

    // Read the keyset proto serialization.
    const reader = BinaryKeysetReader.withUint8Array(serializedKeyset);
    const keysetFromReader = reader.read();

    // Test that it returns the same object as was created.
    assertMessageEquals(keysetFromReader, keyset);
  });

  it('read encrypted, not implemented yet', function() {
    const reader = BinaryKeysetReader.withUint8Array(new Uint8Array(10));

    try {
      reader.readEncrypted();
      fail('An exception should be thrown.');
    } catch (e: any) {
      expect(e.toString()).toBe(ExceptionText.notImplemented());
    }
  });
});

////////////////////////////////////////////////////////////////////////////////
// helper functions and classes for tests
////////////////////////////////////////////////////////////////////////////////

/**
 * Class which holds texts for each type of exception.
 * @final
 */
class ExceptionText {
  static notImplemented(): string {
    return 'SecurityException: Not implemented yet.';
  }

  static nullKeyset(): string {
    return 'SecurityException: Serialized keyset has to be non-null.';
  }

  static invalidSerialization(): string {
    return 'SecurityException: Could not parse the given serialized proto as ' +
        'a keyset proto.';
  }
}

/** Function for creating keys for testing purposes. */
function createDummyKeysetKey(
    keyId: number, outputPrefix: PbOutputPrefixType,
    enabled: boolean): PbKeysetKey {
  const key = new PbKeysetKey();

  if (enabled) {
    key.setStatus(PbKeyStatusType.ENABLED);
  } else {
    key.setStatus(PbKeyStatusType.DISABLED);
  }
  key.setOutputPrefixType(outputPrefix);
  key.setKeyId(keyId);

  // Set some key data.
  key.setKeyData(new PbKeyData());
  key.getKeyData()?.setTypeUrl('SOME_KEY_TYPE_URL_' + keyId.toString());
  key.getKeyData()?.setKeyMaterialType(PbKeyData.KeyMaterialType.SYMMETRIC);
  key.getKeyData()?.setValue(Random.randBytes(10));

  return key;
}
