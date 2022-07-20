/**
 * @license
 * Copyright 2020 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */

import {CryptoFormat} from './crypto_format';
import {PbKeysetKey as PbKeysetKey, PbOutputPrefixType} from './proto';

describe('crypto format test', function() {
  it('constants', async function() {
    expect(CryptoFormat.RAW_PREFIX_SIZE).toBe(0);
    expect(CryptoFormat.NON_RAW_PREFIX_SIZE).toBe(5);
    expect(CryptoFormat.LEGACY_PREFIX_SIZE).toBe(5);
    expect(CryptoFormat.TINK_PREFIX_SIZE).toBe(5);

    expect(CryptoFormat.LEGACY_START_BYTE).toBe(0x00);
    expect(CryptoFormat.TINK_START_BYTE).toBe(0x01);
  });

  it('get output prefix unknown prefix type', async function() {
    let key = new PbKeysetKey()
                  .setOutputPrefixType(PbOutputPrefixType.UNKNOWN_PREFIX)
                  .setKeyId(2864434397);

    try {
      CryptoFormat.getOutputPrefix(key);
    } catch (e: any) {
      expect(e.toString())
          .toBe('SecurityException: Unsupported key prefix type.');
      return;
    }
    fail('An exception should be thrown.');
  });

  it('get output prefix invalid key id', async function() {
    // Key id has to be an unsigned 32-bit integer.
    const invalidKeyIds = [0.2, -10, 2**32];
    let key = new PbKeysetKey().setOutputPrefixType(PbOutputPrefixType.TINK);

    const invalidKeyIdsLength = invalidKeyIds.length;
    for (let i = 0; i < invalidKeyIdsLength; i++) {
      key.setKeyId(invalidKeyIds[i]);
      try {
        CryptoFormat.getOutputPrefix(key);
      } catch (e: any) {
        expect(e.toString())
            .toBe(
                'InvalidArgumentsException: Number has to be unsigned 32-bit integer.');
        continue;
      }
      fail('An exception should be thrown for i: ' + i + '.');
    }
  });

  it('get output prefix tink', async function() {
    const key = new PbKeysetKey()
                    .setOutputPrefixType(PbOutputPrefixType.TINK)
                    .setKeyId(2864434397);
    const expectedResult =
        new Uint8Array([CryptoFormat.TINK_START_BYTE, 0xAA, 0xBB, 0xCC, 0xDD]);

    const actualResult = CryptoFormat.getOutputPrefix(key);
    expect(actualResult).toEqual(expectedResult);
  });

  it('get output prefix legacy', async function() {
    const key = new PbKeysetKey()
                    .setOutputPrefixType(PbOutputPrefixType.LEGACY)
                    .setKeyId(16909060);
    const expectedResult = new Uint8Array(
        [CryptoFormat.LEGACY_START_BYTE, 0x01, 0x02, 0x03, 0x04]);

    const actualResult = CryptoFormat.getOutputPrefix(key);
    expect(actualResult).toEqual(expectedResult);
  });

  it('get output prefix raw', async function() {
    const key = new PbKeysetKey()
                    .setOutputPrefixType(PbOutputPrefixType.RAW)
                    .setKeyId(370491921);
    const expectedResult = new Uint8Array(0);

    const actualResult = CryptoFormat.getOutputPrefix(key);
    expect(actualResult).toEqual(expectedResult);
  });
});
