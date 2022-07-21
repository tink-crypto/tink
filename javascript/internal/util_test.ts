/**
 * @license
 * Copyright 2020 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */

import * as EllipticCurves from '../subtle/elliptic_curves';

import {PbEllipticCurveType, PbHashType, PbKeyData, PbKeyset, PbKeysetKey, PbKeyStatusType, PbOutputPrefixType, PbPointFormat} from './proto';
import * as Util from './util';

////////////////////////////////////////////////////////////////////////////////
// tests
////////////////////////////////////////////////////////////////////////////////

describe('util test', function() {
  // tests for validateKey method
  it('validate key missing key data', async function() {
    const key = createKey().setKeyData(null);

    try {
      Util.validateKey(key);
    } catch (e: any) {
      expect(e.toString())
          .toBe(ExceptionText.InvalidKeyMissingKeyData(key.getKeyId()));
      return;
    }
    fail('An exception should be thrown.');
  });

  it('validate key unknown prefix', async function() {
    const key =
        createKey().setOutputPrefixType(PbOutputPrefixType.UNKNOWN_PREFIX);

    try {
      Util.validateKey(key);
    } catch (e: any) {
      expect(e.toString())
          .toBe(ExceptionText.InvalidKeyUnknownPrefix(key.getKeyId()));
      return;
    }
    fail('An exception should be thrown.');
  });

  it('validate key unknown status', async function() {
    const key = createKey().setStatus(PbKeyStatusType.UNKNOWN_STATUS);

    try {
      Util.validateKey(key);
    } catch (e: any) {
      expect(e.toString())
          .toBe(ExceptionText.InvalidKeyUnknownStatus(key.getKeyId()));
      return;
    }
    fail('An exception should be thrown.');
  });

  it('validate key valid keys', async function() {
    Util.validateKey(createKey());
    Util.validateKey(
        createKey(/* opt_keyId = */ 0xAABBCCDD, /* opt_enabled = */ true));
    Util.validateKey(
        createKey(/* opt_keyId = */ 0xABCDABCD, /* opt_enabled = */ false));
  });

  // tests for validateKeyset method
  it('validate keyset without keys', async function() {
    const keyset = new PbKeyset();

    try {
      Util.validateKeyset(keyset);
    } catch (e: any) {
      expect(e.toString()).toBe(ExceptionText.InvalidKeysetMissingKeys());
      return;
    }
    fail('An exception should be thrown.');
  });

  it('validate keyset disabled primary', async function() {
    const keyset = createKeyset();
    keyset.addKey(
        createKey(/* opt_id = */ 0xFFFFFFFF, /* opt_enabled = */ false));
    keyset.setPrimaryKeyId(0xFFFFFFFF);

    try {
      Util.validateKeyset(keyset);
    } catch (e: any) {
      expect(e.toString()).toBe(ExceptionText.InvalidKeysetDisabledPrimary());
      return;
    }
    fail('An exception should be thrown.');
  });

  it('validate keyset multiple primaries', async function() {
    const keyset = createKeyset();
    const key =
        createKey(/* opt_id = */ 0xFFFFFFFF, /* opt_enabled = */ true);
    keyset.addKey(key);
    keyset.addKey(key);
    keyset.setPrimaryKeyId(0xFFFFFFFF);

    try {
      Util.validateKeyset(keyset);
    } catch (e: any) {
      expect(e.toString()).toBe(ExceptionText.InvalidKeysetMultiplePrimaries());
      return;
    }
    fail('An exception should be thrown.');
  });

  it('validate keyset with invalid key', async function() {
    const keyset = createKeyset();
    const key =
        createKey(4294967295, true).setStatus(PbKeyStatusType.UNKNOWN_STATUS);
    keyset.addKey(key);

    try {
      Util.validateKeyset(keyset);
    } catch (e: any) {
      expect(e.toString())
          .toBe(ExceptionText.InvalidKeyUnknownStatus(key.getKeyId()));
      return;
    }
    fail('An exception should be thrown.');
  });

  it('validate keyset with valid keyset', async function() {
    const keyset = createKeyset();

    Util.validateKeyset(keyset);
  });

  // tests for protoToSubtle methods
  it('curve type proto to subtle', function() {
    expect(Util.curveTypeProtoToSubtle(PbEllipticCurveType.NIST_P256))
        .toBe(EllipticCurves.CurveType.P256);
    expect(Util.curveTypeProtoToSubtle(PbEllipticCurveType.NIST_P384))
        .toBe(EllipticCurves.CurveType.P384);
    expect(Util.curveTypeProtoToSubtle(PbEllipticCurveType.NIST_P521))
        .toBe(EllipticCurves.CurveType.P521);
  });

  it('point format proto to subtle', function() {
    expect(Util.pointFormatProtoToSubtle(PbPointFormat.UNCOMPRESSED))
        .toBe(EllipticCurves.PointFormatType.UNCOMPRESSED);
    expect(Util.pointFormatProtoToSubtle(PbPointFormat.COMPRESSED))
        .toBe(EllipticCurves.PointFormatType.COMPRESSED);
    expect(Util.pointFormatProtoToSubtle(
               PbPointFormat.DO_NOT_USE_CRUNCHY_UNCOMPRESSED))
        .toBe(EllipticCurves.PointFormatType.DO_NOT_USE_CRUNCHY_UNCOMPRESSED);
  });

  it('hash type proto to string', function() {
    expect(Util.hashTypeProtoToString(PbHashType.SHA1)).toBe('SHA-1');
    expect(Util.hashTypeProtoToString(PbHashType.SHA256)).toBe('SHA-256');
    expect(Util.hashTypeProtoToString(PbHashType.SHA512)).toBe('SHA-512');
  });
});


/**
 * Class which holds texts for each type of exception.
 * @final
 */
class ExceptionText {
  // Exceptions for invalid keys.
  static InvalidKeyMissingKeyData(keyId: number): string {
    return 'SecurityException: Key data are missing for key ' + keyId + '.';
  }
  static InvalidKeyUnknownPrefix(keyId: number): string {
    return 'SecurityException: Key ' + keyId +
        ' has unknown output prefix type.';
  }
  static InvalidKeyUnknownStatus(keyId: number): string {
    return 'SecurityException: Key ' + keyId + ' has unknown status.';
  }

  // Exceptions for invalid keysets.
  static InvalidKeysetMissingKeys(): string {
    return 'SecurityException: Keyset should be non null and ' +
        'must contain at least one key.';
  }
  static InvalidKeysetDisabledPrimary(): string {
    return 'SecurityException: Primary key has to be in the keyset and ' +
        'has to be enabled.';
  }
  static InvalidKeysetMultiplePrimaries(): string {
    return 'SecurityException: Primary key has to be unique.';
  }
}

/** Returns a valid PbKeysetKey. */
function createKey(
    opt_id: number = 0x12345678, opt_enabled: boolean = true,
    opt_publicKey: boolean = false): PbKeysetKey {
  const keyData =
      new PbKeyData().setTypeUrl('someTypeUrl').setValue(new Uint8Array(10));
  if (opt_publicKey) {
    keyData.setKeyMaterialType(PbKeyData.KeyMaterialType.ASYMMETRIC_PUBLIC);
  } else {
    keyData.setKeyMaterialType(PbKeyData.KeyMaterialType.SYMMETRIC);
  }

  const key = new PbKeysetKey().setKeyData(keyData);
  if (opt_enabled) {
    key.setStatus(PbKeyStatusType.ENABLED);
  } else {
    key.setStatus(PbKeyStatusType.DISABLED);
  }
  key.setKeyId(opt_id);
  key.setOutputPrefixType(PbOutputPrefixType.TINK);

  return key;
}

/** Returns a valid PbKeyset which primary has id equal to 1. */
function createKeyset(): PbKeyset {
  const numberOfKeys = 20;

  const keyset = new PbKeyset();
  for (let i = 0; i < numberOfKeys; i++) {
    // Key id is never set to 0 as primaryKeyId = 0 if it is unset.
    const key = createKey(i + 1, /* opt_enabled = */ (i % 2) < 1, (i % 4) < 2);
    keyset.addKey(key);
  }

  keyset.setPrimaryKeyId(1);
  return keyset;
}
