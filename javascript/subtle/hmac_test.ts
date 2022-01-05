/**
 * @license
 * Copyright 2020 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */

import * as Bytes from './bytes';
import {fromRawKey as hmacFromRawKey} from './hmac';
import * as Random from './random';

describe('hmac test', function() {
  it('basic', async function() {
    const key = Random.randBytes(16);
    const msg = Random.randBytes(4);
    const hmac = await hmacFromRawKey('SHA-1', key, 10);
    const tag = await hmac.computeMac(msg);
    expect(tag.length).toBe(10);
    expect(await hmac.verifyMac(tag, msg)).toBe(true);
  });

  it('constructor', async function() {
    try {
      await hmacFromRawKey(
          'blah', Random.randBytes(16), 16);  // invalid HMAC algo name
      fail('Should throw an exception.');
      // Preserving old behavior when moving to
      // https://www.typescriptlang.org/tsconfig#useUnknownInCatchVariables
      // tslint:disable-next-line:no-any
    } catch (e: any) {
      expect(e.toString())
          .toBe('InvalidArgumentsException: blah is not supported');
    }

    try {
      await hmacFromRawKey(
          'SHA-1', Random.randBytes(15), 16);  // invalid key size
      // TODO(b/115974209): This case does not throw an exception.
      // Preserving old behavior when moving to
      // https://www.typescriptlang.org/tsconfig#useUnknownInCatchVariables
      // tslint:disable-next-line:no-any
    } catch (e: any) {
      expect(e.toString())
          .toBe('SecurityException: key too short, must be at least 16 bytes');
    }

    try {
      await hmacFromRawKey(
          'SHA-1', Random.randBytes(16), 9);  // tag size too short
      fail('Should throw an exception.');
      // Preserving old behavior when moving to
      // https://www.typescriptlang.org/tsconfig#useUnknownInCatchVariables
      // tslint:disable-next-line:no-any
    } catch (e: any) {
      expect(e.toString())
          .toBe(
              'InvalidArgumentsException: tag too short, must be at least 10 bytes');
    }
    try {
      await hmacFromRawKey(
          'SHA-1', Random.randBytes(16), 21);  // tag size too long
      fail('Should throw an exception.');
      // Preserving old behavior when moving to
      // https://www.typescriptlang.org/tsconfig#useUnknownInCatchVariables
      // tslint:disable-next-line:no-any
    } catch (e: any) {
      expect(e.toString())
          .toBe(
              'InvalidArgumentsException: tag too long, must not be larger than 20 bytes');
    }

    try {
      await hmacFromRawKey(
          'SHA-256', Random.randBytes(15), 16);  // invalid key size
      // TODO(b/115974209): This case does not throw an exception.
      // Preserving old behavior when moving to
      // https://www.typescriptlang.org/tsconfig#useUnknownInCatchVariables
      // tslint:disable-next-line:no-any
    } catch (e: any) {
      expect(e.toString())
          .toBe('SecurityException: key too short, must be at least 16 bytes');
    }

    try {
      await hmacFromRawKey(
          'SHA-256', Random.randBytes(16), 9);  // tag size too short
      fail('Should throw an exception.');
      // Preserving old behavior when moving to
      // https://www.typescriptlang.org/tsconfig#useUnknownInCatchVariables
      // tslint:disable-next-line:no-any
    } catch (e: any) {
      expect(e.toString())
          .toBe(
              'InvalidArgumentsException: tag too short, must be at least 10 bytes');
    }

    try {
      await hmacFromRawKey(
          'SHA-256', Random.randBytes(16), 33);  // tag size too long
      fail('Should throw an exception.');
      // Preserving old behavior when moving to
      // https://www.typescriptlang.org/tsconfig#useUnknownInCatchVariables
      // tslint:disable-next-line:no-any
    } catch (e: any) {
      expect(e.toString())
          .toBe(
              'InvalidArgumentsException: tag too long, must not be larger than 32 bytes');
    }

    try {
      await hmacFromRawKey(
          'SHA-512', Random.randBytes(15), 16);  // invalid key size
      // TODO(b/115974209): This case does not throw an exception.

      // Preserving old behavior when moving to
      // https://www.typescriptlang.org/tsconfig#useUnknownInCatchVariables
      // tslint:disable-next-line:no-any
    } catch (e: any) {
      expect(e.toString())
          .toBe('SecurityException: key too short, must be at least 16 bytes');
    }

    try {
      await hmacFromRawKey(
          'SHA-512', Random.randBytes(16), 9);  // tag size too short
      fail('Should throw an exception.');
      // Preserving old behavior when moving to
      // https://www.typescriptlang.org/tsconfig#useUnknownInCatchVariables
      // tslint:disable-next-line:no-any
    } catch (e: any) {
      expect(e.toString())
          .toBe(
              'InvalidArgumentsException: tag too short, must be at least 10 bytes');
    }

    try {
      await hmacFromRawKey(
          'SHA-512', Random.randBytes(16), 65);  // tag size too long
      fail('Should throw an exception.');
      // Preserving old behavior when moving to
      // https://www.typescriptlang.org/tsconfig#useUnknownInCatchVariables
      // tslint:disable-next-line:no-any
    } catch (e: any) {
      expect(e.toString())
          .toBe(
              'InvalidArgumentsException: tag too long, must not be larger than 64 bytes');
    }
  });

  it('constructor, invalid tag sizes', async function() {
    try {
      await hmacFromRawKey('SHA-512', Random.randBytes(16), NaN);
      fail('Should throw an exception.');
      // Preserving old behavior when moving to
      // https://www.typescriptlang.org/tsconfig#useUnknownInCatchVariables
      // tslint:disable-next-line:no-any
    } catch (e: any) {
      expect(e.toString())
          .toBe(
              'InvalidArgumentsException: invalid tag size, must be an integer');
    }

    try {
      await hmacFromRawKey('SHA-512', Random.randBytes(16), 12.5);
      fail('Should throw an exception.');
      // Preserving old behavior when moving to
      // https://www.typescriptlang.org/tsconfig#useUnknownInCatchVariables
      // tslint:disable-next-line:no-any
    } catch (e: any) {
      expect(e.toString())
          .toBe(
              'InvalidArgumentsException: invalid tag size, must be an integer');
    }
  });

  it('modify', async function() {
    const key = Random.randBytes(16);
    const msg = Random.randBytes(8);
    const hmac = await hmacFromRawKey('SHA-1', key, 20);
    const tag = await hmac.computeMac(msg);

    // Modify tag.
    for (let i = 0; i < tag.length; i++) {
      const tag1 = new Uint8Array(tag);
      tag1[i] = tag[i] ^ 0xff;
      expect(await hmac.verifyMac(tag1, msg)).toBe(false);
    }

    // Modify msg.
    for (let i = 0; i < msg.length; i++) {
      const msg1 = new Uint8Array(msg);
      msg1[i] = msg1[i] ^ 0xff;
      expect(await hmac.verifyMac(tag, msg1)).toBe(false);
    }
  });

  it('with test vectors', async function() {
    // Test data from
    // http://csrc.nist.gov/groups/STM/cavp/message-authentication.html#testing.
    const NIST_TEST_VECTORS = [
      {
        'algo': 'SHA-1',
        'key':
            '816aa4c3ee066310ac1e6666cf830c375355c3c8ba18cfe1f50a48c988b46272',
        'message':
            '220248f5e6d7a49335b3f91374f18bb8b0ff5e8b9a5853f3cfb293855d78301d' +
            '837a0a2eb9e4f056f06c08361bd07180ee802651e69726c28910d2baef379606' +
            '815dcbab01d0dc7acb0ba8e65a2928130da0522f2b2b3d05260885cf1c64f14c' +
            'a3145313c685b0274bf6a1cb38e4f99895c6a8cc72fbe0e52c01766fede78a1a',
        'tag': '17cb2e9e98b748b5ae0f7078ea5519e5'
      },
      {
        'algo': 'SHA-256',
        'key':
            '6f35628d65813435534b5d67fbdb54cb33403d04e843103e6399f806cb5df95' +
            'febbdd61236f33245',
        'message':
            '752cff52e4b90768558e5369e75d97c69643509a5e5904e0a386cbe4d0970ef7' +
            '3f918f675945a9aefe26daea27587e8dc909dd56fd0468805f834039b345f855' +
            'cfe19c44b55af241fff3ffcd8045cd5c288e6c4e284c3720570b58e4d47b8fee' +
            'edc52fd1401f698a209fccfa3b4c0d9a797b046a2759f82a54c41ccd7b5f592b',
        'tag': '05d1243e6465ed9620c9aec1c351a186'
      },
      {
        'algo': 'SHA-512',
        'key':
            '726374c4b8df517510db9159b730f93431e0cd468d4f3821eab0edb93abd0fba' +
            '46ab4f1ef35d54fec3d85fa89ef72ff3d35f22cf5ab69e205c10afcdf4aaf113' +
            '38dbb12073474fddb556e60b8ee52f91163ba314303ee0c910e64e87fbf30221' +
            '4edbe3f2',
        'message':
            'ac939659dc5f668c9969c0530422e3417a462c8b665e8db25a883a625f7aa59b' +
            '89c5ad0ece5712ca17442d1798c6dea25d82c5db260cb59c75ae650be56569c1' +
            'bd2d612cc57e71315917f116bbfa65a0aeb8af7840ee83d3e7101c52cf652d27' +
            '73531b7a6bdd690b846a741816c860819270522a5b0cdfa1d736c501c583d916',

        'tag':
            'bd3d2df6f9d284b421a43e5f9cb94bc4ff88a88243f1f0133bad0fb1791f6569'
      },
    ];
    for (let i = 0; i < NIST_TEST_VECTORS.length; i++) {
      const testVector = NIST_TEST_VECTORS[i];
      const key = Bytes.fromHex(testVector['key']);
      const message = Bytes.fromHex(testVector['message']);
      const tag = Bytes.fromHex(testVector['tag']);
      const hmac = await hmacFromRawKey(testVector['algo'], key, tag.length);
      expect(await hmac.verifyMac(tag, message)).toBe(true);
    }
  });
});
