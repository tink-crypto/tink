/**
 * @license
 * Copyright 2020 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */

import * as Bytes from './bytes';
import * as Hkdf from './hkdf';
import * as Random from './random';

describe('hkdf test', function() {
  it('constructor', async function() {
    const ikm = Random.randBytes(16);
    const info = Random.randBytes(16);
    try {
      await Hkdf.compute(0, 'SHA-256', ikm, info);  // 0 output size
      fail('Should throw an exception.');
      // Preserving old behavior when moving to
      // https://www.typescriptlang.org/tsconfig#useUnknownInCatchVariables
      // tslint:disable-next-line:no-any
    } catch (e: any) {
      expect(e.toString())
          .toBe('InvalidArgumentsException: size must be positive');
    }

    try {
      await Hkdf.compute(-1, 'SHA-256', ikm, info);  // negative output size
      fail('Should throw an exception.');
      // Preserving old behavior when moving to
      // https://www.typescriptlang.org/tsconfig#useUnknownInCatchVariables
      // tslint:disable-next-line:no-any
    } catch (e: any) {
      expect(e.toString())
          .toBe('InvalidArgumentsException: size must be positive');
    }

    try {
      await Hkdf.compute(
          /** 255 * digestSize + 1 */ (255 * 20) + 1, 'SHA-1', ikm,
          info);  // size too large
      fail('Should throw an exception.');
      // Preserving old behavior when moving to
      // https://www.typescriptlang.org/tsconfig#useUnknownInCatchVariables
      // tslint:disable-next-line:no-any
    } catch (e: any) {
      expect(e.toString()).toBe('InvalidArgumentsException: size too large');
    }

    try {
      await Hkdf.compute(
          /** 255 * digestSize + 1 */ (255 * 32) + 1, 'SHA-256', ikm,
          info);  // size too large
      fail('Should throw an exception.');
      // Preserving old behavior when moving to
      // https://www.typescriptlang.org/tsconfig#useUnknownInCatchVariables
      // tslint:disable-next-line:no-any
    } catch (e: any) {
      expect(e.toString()).toBe('InvalidArgumentsException: size too large');
    }

    try {
      await Hkdf.compute(
          /** 255 * digestSize + 1 */ (255 * 64) + 1, 'SHA-512', ikm,
          info);  // size too large
      fail('Should throw an exception.');
      // Preserving old behavior when moving to
      // https://www.typescriptlang.org/tsconfig#useUnknownInCatchVariables
      // tslint:disable-next-line:no-any
    } catch (e: any) {
      expect(e.toString()).toBe('InvalidArgumentsException: size too large');
    }
  });

  it('constructor, non integer output size', async function() {
    const ikm = Random.randBytes(16);
    const info = Random.randBytes(16);
    try {
      await Hkdf.compute(NaN, 'SHA-256', ikm, info);
      fail('Should throw an exception.');
      // Preserving old behavior when moving to
      // https://www.typescriptlang.org/tsconfig#useUnknownInCatchVariables
      // tslint:disable-next-line:no-any
    } catch (e: any) {
      expect(e.toString())
          .toBe('InvalidArgumentsException: size must be an integer');
    }

    try {
      await Hkdf.compute(1.5, 'SHA-256', ikm, info);
      fail('Should throw an exception.');
      // Preserving old behavior when moving to
      // https://www.typescriptlang.org/tsconfig#useUnknownInCatchVariables
      // tslint:disable-next-line:no-any
    } catch (e: any) {
      expect(e.toString())
          .toBe('InvalidArgumentsException: size must be an integer');
    }
  });

  it('with test vectors', async function() {
    // Test cases are specified in Appendix A of RFC 5869.
    const TEST_VECTORS = [
      {
        'hash': 'SHA-256',
        'output':
            '3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865',
        'outputSize': 42,
        'ikm': '0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b',
        'salt': '000102030405060708090a0b0c',
        'info': 'f0f1f2f3f4f5f6f7f8f9',
      },
      {
        'hash': 'SHA-256',
        'output':
            'b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c' +
            '59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71' +
            'cc30c58179ec3e87c14c01d5c1f3434f1d87',
        'outputSize': 82,
        'ikm':
            '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f' +
            '202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f' +
            '404142434445464748494a4b4c4d4e4f',
        'salt':
            '606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f' +
            '808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f' +
            'a0a1a2a3a4a5a6a7a8a9aaabacadaeaf',
        'info':
            'b0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecf' +
            'd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeef' +
            'f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff',
      },
      // Salt is empty
      {
        'hash': 'SHA-256',
        'output':
            '8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d' +
            '9d201395faa4b61a96c8',
        'outputSize': 42,
        'ikm': '0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b',
        'salt': '',
        'info': '',
      },
      {
        'hash': 'SHA-1',
        'output':
            '085a01ea1b10f36933068b56efa5ad81a4f14b822f5b091568a9cdd4f155fda2c22e422478d305f3f896',
        'outputSize': 42,
        'ikm': '0b0b0b0b0b0b0b0b0b0b0b',
        'salt': '000102030405060708090a0b0c',
        'info': 'f0f1f2f3f4f5f6f7f8f9',
      },
      {
        'hash': 'SHA-1',
        'output':
            '0bd770a74d1160f7c9f12cd5912a06ebff6adcae899d92191fe4305673ba2ffe' +
            '8fa3f1a4e5ad79f3f334b3b202b2173c486ea37ce3d397ed034c7f9dfeb15c5e' +
            '927336d0441f4c4300e2cff0d0900b52d3b4',
        'outputSize': 82,
        'ikm':
            '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f' +
            '202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f' +
            '404142434445464748494a4b4c4d4e4f',
        'salt':
            '606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f' +
            '808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f' +
            'a0a1a2a3a4a5a6a7a8a9aaabacadaeaf',
        'info':
            'b0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecf' +
            'd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeef' +
            'f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff',
      },
      // Salt is empty
      {
        'hash': 'SHA-1',
        'output':
            '0ac1af7002b3d761d1e55298da9d0506b9ae52057220a306e07b6b87e8df21d0' +
            'ea00033de03984d34918',
        'outputSize': 42,
        'ikm': '0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b',
        'salt': '',
        'info': '',
      },
      // Salt is empty
      {
        'hash': 'SHA-1',
        'output':
            '2c91117204d745f3500d636a62f64f0ab3bae548aa53d423b0d1f27ebba6f5e5' +
            '673a081d70cce7acfc48',
        'outputSize': 42,
        'ikm': '0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c',
        'salt': '',
        'info': '',
      },
    ];
    for (let i = 0; i < TEST_VECTORS.length; i++) {
      const testVector = TEST_VECTORS[i];
      const ikm = Bytes.fromHex(testVector['ikm']);
      const salt = Bytes.fromHex(testVector['salt']);
      const info = Bytes.fromHex(testVector['info']);
      const hkdf = await Hkdf.compute(
          testVector['outputSize'], testVector['hash'], ikm, info, salt);
      expect(testVector['output']).toBe(Bytes.toHex(hkdf));
    }
  });
});
