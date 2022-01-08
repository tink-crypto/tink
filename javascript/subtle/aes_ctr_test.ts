/**
 * @license
 * Copyright 2020 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */

import {fromRawKey as aesCtrFromRawKey} from './aes_ctr';
import * as Bytes from './bytes';
import * as Random from './random';

describe('aes ctr test', function() {
  beforeEach(function() {
    // Use a generous promise timeout for running continuously.
    jasmine.DEFAULT_TIMEOUT_INTERVAL = 1000 * 1000;  // 1000s
  });

  afterEach(function() {
    // Reset the timeout.
    jasmine.DEFAULT_TIMEOUT_INTERVAL = 1000;  // 1s
  });

  it('basic', async function() {
    // Set longer time for promiseTimout as the test sometimes takes longer than
    // 1 second in Firefox.
    const key = Random.randBytes(16);
    for (let i = 0; i < 100; i++) {
      const msg = Random.randBytes(20);
      const cipher = await aesCtrFromRawKey(key, 16);
      let ciphertext = await cipher.encrypt(msg);
      let plaintext = await cipher.decrypt(ciphertext);
      expect(Bytes.toHex(plaintext)).toBe(Bytes.toHex(msg));
    }
  });

  it('probabilistic encryption', async function() {
    const cipher = await aesCtrFromRawKey(Random.randBytes(16), 16);
    const msg = Random.randBytes(20);
    const results = new Set();
    for (let i = 0; i < 100; i++) {
      const ciphertext = await cipher.encrypt(msg);
      results.add(Bytes.toHex(ciphertext));
    }
    expect(results.size).toBe(100);
  });

  it('constructor', async function() {
    try {
      await aesCtrFromRawKey(Random.randBytes(16), 11);  // IV size too short
      fail('Should throw an exception.');
      // Preserving old behavior when moving to
      // https://www.typescriptlang.org/tsconfig#useUnknownInCatchVariables
      // tslint:disable-next-line:no-any
    } catch (e: any) {
      expect(e.toString())
          .toBe(
              'SecurityException: invalid IV length, must be at least 12 and at most 16');
    }
    try {
      await aesCtrFromRawKey(Random.randBytes(16), 17);  // IV size too long
      fail('Should throw an exception.');
      // Preserving old behavior when moving to
      // https://www.typescriptlang.org/tsconfig#useUnknownInCatchVariables
      // tslint:disable-next-line:no-any
    } catch (e: any) {
      expect(e.toString())
          .toBe(
              'SecurityException: invalid IV length, must be at least 12 and at most 16');
    }
    try {
      await aesCtrFromRawKey(
          Random.randBytes(24), 12);  // 192-bit keys not supported
      fail('Should throw an exception.');
      // Preserving old behavior when moving to
      // https://www.typescriptlang.org/tsconfig#useUnknownInCatchVariables
      // tslint:disable-next-line:no-any
    } catch (e: any) {
      expect(e.toString())
          .toBe('InvalidArgumentsException: unsupported AES key size: 24');
    }
  });

  it('constructor, invalid iv sizes', async function() {
    try {
      await aesCtrFromRawKey(Random.randBytes(16), NaN);
      fail('Should throw an exception.');
      // Preserving old behavior when moving to
      // https://www.typescriptlang.org/tsconfig#useUnknownInCatchVariables
      // tslint:disable-next-line:no-any
    } catch (e: any) {
      expect(e.toString())
          .toBe('SecurityException: invalid IV length, must be an integer');
    }

    try {
      await aesCtrFromRawKey(Random.randBytes(16), 12.5);
      fail('Should throw an exception.');
      // Preserving old behavior when moving to
      // https://www.typescriptlang.org/tsconfig#useUnknownInCatchVariables
      // tslint:disable-next-line:no-any
    } catch (e: any) {
      expect(e.toString())
          .toBe('SecurityException: invalid IV length, must be an integer');
    }

    try {
      await aesCtrFromRawKey(Random.randBytes(16), 0);
      fail('Should throw an exception.');
      // Preserving old behavior when moving to
      // https://www.typescriptlang.org/tsconfig#useUnknownInCatchVariables
      // tslint:disable-next-line:no-any
    } catch (e: any) {
      expect(e.toString())
          .toBe(
              'SecurityException: invalid IV length, must be at least 12 and at most 16');
    }
  });

  it('with test vectors', async function() {
    // Test data from NIST SP 800-38A pp 55.
    const NIST_TEST_VECTORS = [
      {
        'key': '2b7e151628aed2a6abf7158809cf4f3c',
        'message':
            '6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51' +
            '30c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710',
        'ciphertext':
            '874d6191b620e3261bef6864990db6ce9806f66b7970fdff8617187bb9fffdff' +
            '5ae4df3edbd5d35e5b4f09020db03eab1e031dda2fbe03d1792170a0f3009cee',
        'iv': 'f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff'
      },
    ];
    for (let i = 0; i < NIST_TEST_VECTORS.length; i++) {
      const testVector = NIST_TEST_VECTORS[i];
      const key = Bytes.fromHex(testVector['key']);
      const iv = Bytes.fromHex(testVector['iv']);
      const msg = Bytes.fromHex(testVector['message']);
      const ciphertext = Bytes.fromHex(testVector['ciphertext']);
      const aesctr = await aesCtrFromRawKey(key, iv.length);
      const plaintext = await aesctr.decrypt(Bytes.concat(iv, ciphertext));
      expect(Bytes.toHex(plaintext)).toBe(Bytes.toHex(msg));
    }
  });
});
