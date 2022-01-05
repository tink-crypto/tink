/**
 * @license
 * Copyright 2020 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */

import * as Bytes from './bytes';
import {EciesHkdfKemRecipient, fromJsonWebKey as recipientFromJsonWebKey} from './ecies_hkdf_kem_recipient';
import {fromJsonWebKey as senderFromJsonWebKey} from './ecies_hkdf_kem_sender';
import * as EllipticCurves from './elliptic_curves';
import * as Random from './random';

describe('ecies hkdf kem recipient test', function() {
  beforeEach(function() {
    // Use a generous promise timeout for running continuously.
    jasmine.DEFAULT_TIMEOUT_INTERVAL = 1000 * 1000;  // 1000s
  });

  afterEach(function() {
    // Reset the promise timeout to default value.
    jasmine.DEFAULT_TIMEOUT_INTERVAL = 1000;  // 1s
  });

  it('encap decap', async function() {
    const keyPair = await EllipticCurves.generateKeyPair('ECDH', 'P-256');
    const publicKey = await EllipticCurves.exportCryptoKey(keyPair.publicKey!);
    const privateKey = await EllipticCurves.exportCryptoKey(keyPair.privateKey!);
    const sender = await senderFromJsonWebKey(publicKey);
    const recipient = await recipientFromJsonWebKey(privateKey);
    for (let i = 1; i < 20; i++) {
      const keySizeInBytes = i;
      const pointFormat = EllipticCurves.PointFormatType.UNCOMPRESSED;
      const hkdfHash = 'SHA-256';
      const hkdfInfo = Random.randBytes(i);
      const hkdfSalt = Random.randBytes(i);

      const kemKeyToken = await sender.encapsulate(
          keySizeInBytes, pointFormat, hkdfHash, hkdfInfo, hkdfSalt);
      const key = await recipient.decapsulate(
          kemKeyToken['token'], keySizeInBytes, pointFormat, hkdfHash, hkdfInfo,
          hkdfSalt);

      expect(kemKeyToken['key'].length).toBe(keySizeInBytes);
      expect(Bytes.toHex(kemKeyToken['key'])).toBe(Bytes.toHex(key));
    }
  });

  it('decap, non integer key size', async function() {
    const keyPair = await EllipticCurves.generateKeyPair('ECDH', 'P-256');
    const publicKey = await EllipticCurves.exportCryptoKey(keyPair.publicKey!);
    const privateKey =
        await EllipticCurves.exportCryptoKey(keyPair.privateKey!);
    const sender = await senderFromJsonWebKey(publicKey);
    const recipient = await recipientFromJsonWebKey(privateKey);
    const keySizeInBytes = 16;
    const pointFormat = EllipticCurves.PointFormatType.UNCOMPRESSED;
    const hkdfHash = 'SHA-256';
    const hkdfInfo = Random.randBytes(16);
    const hkdfSalt = Random.randBytes(16);
    const kemKeyToken = await sender.encapsulate(
        keySizeInBytes, pointFormat, hkdfHash, hkdfInfo, hkdfSalt);

    try {
      await recipient.decapsulate(
          kemKeyToken['token'], NaN, pointFormat, hkdfHash, hkdfInfo, hkdfSalt);
      fail('An exception should be thrown.');
      // Preserving old behavior when moving to
      // https://www.typescriptlang.org/tsconfig#useUnknownInCatchVariables
      // tslint:disable-next-line:no-any
    } catch (e: any) {
      expect(e.toString())
          .toBe('InvalidArgumentsException: size must be an integer');
    }

    try {
      await recipient.decapsulate(
          kemKeyToken['token'], 1.8, pointFormat, hkdfHash, hkdfInfo, hkdfSalt);
      fail('An exception should be thrown.');
      // Preserving old behavior when moving to
      // https://www.typescriptlang.org/tsconfig#useUnknownInCatchVariables
      // tslint:disable-next-line:no-any
    } catch (e: any) {
      expect(e.toString())
          .toBe('InvalidArgumentsException: size must be an integer');
    }
  });

  it('new instance, invalid parameters', async function() {
    // Test newInstance with public key instead private key.
    const keyPair = await EllipticCurves.generateKeyPair('ECDH', 'P-256');
    const publicKey = await EllipticCurves.exportCryptoKey(keyPair.publicKey!);
    try {
      await recipientFromJsonWebKey(publicKey);
      fail('An exception should be thrown.');
    } catch (e) {
    }
  });

  it('new instance, invalid private key', async function() {
    for (const testVector of TEST_VECTORS) {
      const ellipticCurveString = EllipticCurves.curveToString(testVector.crv);
      const privateJwk = EllipticCurves.pointDecode(
          ellipticCurveString, testVector.pointFormat,
          Bytes.fromHex(testVector.privateKeyPoint));
      privateJwk['d'] = Bytes.toBase64(
          Bytes.fromHex(testVector.privateKeyValue), /* opt_webSafe = */ true);

      // Change the x value such that the key si no more valid. Recipient should
      // either throw an exception or ignore the x value and compute the same
      // output value.
      const xLength = EllipticCurves.fieldSizeInBytes(testVector.crv);
      privateJwk['x'] =
          Bytes.toBase64(new Uint8Array(xLength), /* opt_webSafe = */ true);
      let output;
      try {
        const recipient = await recipientFromJsonWebKey(privateJwk);
        const hkdfInfo = Bytes.fromHex(testVector.hkdfInfo);
        const salt = Bytes.fromHex(testVector.salt);
        output = await recipient.decapsulate(
            Bytes.fromHex(testVector.token), testVector.outputLength,
            testVector.pointFormat, testVector.hashType, hkdfInfo, salt);
      } catch (e) {
        // Everything works properly if exception was thrown.
        return;
      }
      // If there was no exception, the output should be still correct (x value
      // should be ignored during the computation).
      expect(Bytes.toHex(output)).toBe(testVector.expectedOutput);
    }
  });

  it('constructor, invalid parameters', async function() {
    // Test public key instead of private key.
    const keyPair = await EllipticCurves.generateKeyPair('ECDH', 'P-256');
    try {
      new EciesHkdfKemRecipient(keyPair.publicKey!);
      fail('An exception should be thrown.');
      // Preserving old behavior when moving to
      // https://www.typescriptlang.org/tsconfig#useUnknownInCatchVariables
      // tslint:disable-next-line:no-any
    } catch (e: any) {
      expect(e.toString())
          .toBe('SecurityException: Expected crypto key of type: private.');
    }
  });

  it('encap decap, different params', async function() {
    const curveTypes = [
      EllipticCurves.CurveType.P256, EllipticCurves.CurveType.P384,
      EllipticCurves.CurveType.P521
    ];
    const hashTypes = ['SHA-1', 'SHA-256', 'SHA-512'];
    for (const curve of curveTypes) {
      const curveString = EllipticCurves.curveToString(curve);
      for (const hashType of hashTypes) {
        const keyPair =
            await EllipticCurves.generateKeyPair('ECDH', curveString);
        const keySizeInBytes = 32;
        const pointFormat = EllipticCurves.PointFormatType.UNCOMPRESSED;
        const hkdfInfo = Random.randBytes(8);
        const hkdfSalt = Random.randBytes(16);

        const publicKey =
            await EllipticCurves.exportCryptoKey(keyPair.publicKey!);
        const sender = await senderFromJsonWebKey(publicKey);
        const kemKeyToken = await sender.encapsulate(
            keySizeInBytes, pointFormat, hashType, hkdfInfo, hkdfSalt);

        const privateKey =
            await EllipticCurves.exportCryptoKey(keyPair.privateKey!);
        const recipient = await recipientFromJsonWebKey(privateKey);
        const key = await recipient.decapsulate(
            kemKeyToken['token'], keySizeInBytes, pointFormat, hashType,
            hkdfInfo, hkdfSalt);

        expect(kemKeyToken['key'].length).toBe(keySizeInBytes);
        expect(Bytes.toHex(kemKeyToken['key'])).toBe(Bytes.toHex(key));
      }
    }
  });

  it('encap decap, modified token', async function() {
    const curveTypes = [
      EllipticCurves.CurveType.P256, EllipticCurves.CurveType.P384,
      EllipticCurves.CurveType.P521
    ];
    const hashTypes = ['SHA-1', 'SHA-256', 'SHA-512'];
    for (let curve of curveTypes) {
      const curveString = EllipticCurves.curveToString(curve);
      for (let hashType of hashTypes) {
        const keyPair =
            await EllipticCurves.generateKeyPair('ECDH', curveString);
        const privateKey =
            await EllipticCurves.exportCryptoKey(keyPair.privateKey!);
        const recipient = await recipientFromJsonWebKey(privateKey);
        const keySizeInBytes = 32;
        const pointFormat = EllipticCurves.PointFormatType.UNCOMPRESSED;
        const hkdfInfo = Random.randBytes(8);
        const hkdfSalt = Random.randBytes(16);

        // Create invalid token (EC point), while preserving the 0x04 prefix
        // byte.
        const token = Random.randBytes(
            EllipticCurves.encodingSizeInBytes(curve, pointFormat));
        token[0] = 0x04;
        try {
          await recipient.decapsulate(
              token, keySizeInBytes, pointFormat, hashType, hkdfInfo, hkdfSalt);
          fail('Should throw an exception');
        } catch (e) {
        }
      }
    }
  });

  it('decapsulate, test vectors generated by java', async function() {
    for (const testVector of TEST_VECTORS) {
      const ellipticCurveString = EllipticCurves.curveToString(testVector.crv);
      const privateJwk = EllipticCurves.pointDecode(
          ellipticCurveString, testVector.pointFormat,
          Bytes.fromHex(testVector.privateKeyPoint));
      privateJwk['d'] = Bytes.toBase64(
          Bytes.fromHex(testVector.privateKeyValue), /* opt_webSafe = */ true);
      const recipient = await recipientFromJsonWebKey(privateJwk);
      const hkdfInfo = Bytes.fromHex(testVector.hkdfInfo);
      const salt = Bytes.fromHex(testVector.salt);
      const output = await recipient.decapsulate(
          Bytes.fromHex(testVector.token), testVector.outputLength,
          testVector.pointFormat, testVector.hashType, hkdfInfo, salt);
      expect(Bytes.toHex(output)).toBe(testVector.expectedOutput);
    }
  });
});


class TestVector {
  constructor(
      readonly crv: EllipticCurves.CurveType, readonly hashType: string,
      readonly pointFormat: EllipticCurves.PointFormatType,
      readonly token: string, readonly privateKeyPoint: string,
      readonly privateKeyValue: string, readonly salt: string,
      readonly hkdfInfo: string, readonly outputLength: number,
      readonly expectedOutput: string) {}
}

// Test vectors generated by Java version of Tink.
//
// Token (i.e. sender public key) and privateKeyPoint values are in UNCOMPRESSED
// EcPoint encoding (i.e. it has prefix '04' followed by x and y values).
const TEST_VECTORS: TestVector[] = [
  new TestVector(
      EllipticCurves.CurveType.P256, 'SHA-256',
      EllipticCurves.PointFormatType.UNCOMPRESSED,
      /* token = */ '04' +
          '5cdd8e426d11970a610f0e5f9b27f247a421c477b379f2ff3fd3bac50dfff9ff' +
          '7cada79ab1de9ce4aeaff45fcd2628d1b6d7ecac99d4c26409d4ab8a362c8e7a',
      /* privateKeyPoint = */ '04' +
          '4adf0fff84b995bb97af250128a3d779c86ba3cd7e5c0fa2c10895d0b995aaee' +
          'cdced57616ebb04c808f191c2bf3848c495dcfddcdd1bb73d8ea7a15c642af05',
      /* privateKeyValue = */
      'da73e10f7d81483daa63438b982c879706bcf8fef8c7c4d3071c3ef2367714f3',
      /* salt = */ 'abcdef',
      /* hkdfInfo = */ 'aaaaaaaaaaaaaaaa',
      /* outputLength = */ 32,
      /* expectedOutput = */
      'aeeee35a14967310798f037e2f126e2e326369115eb9e2d1a34d9c6761f60511'),
  new TestVector(
      EllipticCurves.CurveType.P384, 'SHA-1',
      EllipticCurves.PointFormatType.UNCOMPRESSED,
      /* token = */ '04' +
          '75bc8a2e6cf80ce2e0a1cd60ab3d68e4d357b58ff69f0de14b7ec13c58a79750496e07db3f933167148d80730b96f000' +
          '9389967de410535ca3e103e7ce73dae9525f934589a6cd1fca37e61411985788dcedc71b35ef63b7365e391f6e2a945f',
      /* privateKeyPoint = */ '04' +
          '5f81886c4202897355b1da79348d53abd9e9119a7de6f5f10dfe751f7ca9c807035c029bac59499337c4af185fe61728' +
          'f132bfb234365a9c61e1e56c11acca3bee6621961c7c38eb9dcbd39b332fd35006876dccdb206a7b2d43cf70589c3356',
      /* privateKeyValue = */
      '544b5f32731d6277fa71e756f0b2d6840f62e6b744a8b8cdf91f8cf29e6d8562f6237369721f756ab044711e0d42c53c',
      /* salt = */ 'ababcdcd',
      /* hkdfInfo = */ '100000000000000001',
      /* outputLength = */ 32,
      /* expectedOutput = */
      '7a25c525eabaa0d994c27f7661a208b5ea25c2a778198237de6e4f235cd64a33'),
  new TestVector(
      EllipticCurves.CurveType.P521, 'SHA-512',
      EllipticCurves.PointFormatType.UNCOMPRESSED,
      /* token = */ '04' +
          '0075192f8decddf7a0371b2c859aad738cc5424fa70e74b560070ed8309ae8a6064b06f9aaad8020ac8620e62a6c1196efa44180d325a36a54945743b9382bd49bc1' +
          '000dfa1e30b228e975998b7afeaaf30235ec505960e58bf3269b69fffcbce9f15fc1441fab2ed97f554ae4bde8b956efb2372c5b330cb1aa0ab81b99e792acd7f5a8',
      /* privateKeyPoint = */ '04' +
          '00e57037a96bcbca532ef2f75646d825304ea716bbc9c4bf953455074347158f4818122c76e26a4cf94b39f451b7f5960b9cda43d49999ddc401c1be7f082052b387' +
          '0147197ba83ec55c8b02e6cbe7b49ce6d6c238edb89561bde6b4574a585c684379d8040888117866823258216344a7268dc696c3a2d192824a1e693609b44661fc2c',
      /* privateKeyValue = */
      '001e5410117d22e95c5768b82a786dd66fa8c326b938a3a81fdd6113499437ae9f74e9f876adf085c187c6a147abc13460b8ed3050a6b228005426b61f2b616a79c6',
      /* salt = */ '00001111',
      /* hkdfInfo = */ '1234123412341234',
      /* outputLength = */ 32,
      /* expectedOutput = */
      '3f7f64c7aba2cb012c9b5a952385290604b3b5843ec6e6714647a9c9d6ac87be')
];
