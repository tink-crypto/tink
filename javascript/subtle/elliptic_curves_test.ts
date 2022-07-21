/**
 * @license
 * Copyright 2020 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */

import {assertExists} from '../testing/internal/test_utils';

import * as Bytes from './bytes';
import * as EllipticCurves from './elliptic_curves';
import * as Random from './random';
import {WYCHEPROOF_ECDH_TEST_VECTORS} from './wycheproof_ecdh_test_vectors';

describe('elliptic curves test', function() {
  beforeEach(function() {
    // Use a generous promise timeout for running continuously.
    jasmine.DEFAULT_TIMEOUT_INTERVAL = 1000 * 1000;  // 1000s
  });

  afterEach(function() {
    // Reset the promise timeout to default value.
    jasmine.DEFAULT_TIMEOUT_INTERVAL = 1000;  // 1s
  });

  it('compute ecdh shared secret', async function() {
    const aliceKeyPair = await EllipticCurves.generateKeyPair('ECDH', 'P-256');
    const bobKeyPair = await EllipticCurves.generateKeyPair('ECDH', 'P-256');
    const sharedSecret1 = await EllipticCurves.computeEcdhSharedSecret(
        aliceKeyPair.privateKey!, bobKeyPair.publicKey!);
    const sharedSecret2 = await EllipticCurves.computeEcdhSharedSecret(
        bobKeyPair.privateKey!, aliceKeyPair.publicKey!);
    expect(Bytes.toHex(sharedSecret2)).toBe(Bytes.toHex(sharedSecret1));
  });

  it('wycheproof, wycheproof webcrypto', async function() {
    for (const testGroup of WYCHEPROOF_ECDH_TEST_VECTORS['testGroups']) {
      let errors = '';
      for (const test of testGroup['tests']) {
        errors += await runWycheproofTest(test);
      }
      if (errors !== '') {
        fail(errors);
      }
    }
  });

  // Test that both ECDH public and private key are defined in the result.
  it('generate key pair e c d h', async function() {
    const curveTypes = [
      EllipticCurves.CurveType.P256, EllipticCurves.CurveType.P384,
      EllipticCurves.CurveType.P521
    ];
    for (const curve of curveTypes) {
      const curveTypeString = EllipticCurves.curveToString(curve);
      const keyPair =
          await EllipticCurves.generateKeyPair('ECDH', curveTypeString);
      expect(keyPair.privateKey! != null).toBe(true);
      expect(keyPair.publicKey! != null).toBe(true);
    }
  });

  // Test that both ECDSA public and private key are defined in the result.
  it('generate key pair e c d s a', async function() {
    const curveTypes = [
      EllipticCurves.CurveType.P256, EllipticCurves.CurveType.P384,
      EllipticCurves.CurveType.P521
    ];
    for (const curve of curveTypes) {
      const curveTypeString = EllipticCurves.curveToString(curve);
      const keyPair =
          await EllipticCurves.generateKeyPair('ECDSA', curveTypeString);
      expect(keyPair.privateKey! != null).toBe(true);
      expect(keyPair.publicKey! != null).toBe(true);
    }
  });

  // Test that when ECDH crypto key is exported and imported it gives the same
  // key as the original one.
  it('import export crypto key e c d h', async function() {
    const curveTypes = [
      EllipticCurves.CurveType.P256, EllipticCurves.CurveType.P384,
      EllipticCurves.CurveType.P521
    ];
    for (const curve of curveTypes) {
      const curveTypeString = EllipticCurves.curveToString(curve);
      const keyPair =
          await EllipticCurves.generateKeyPair('ECDH', curveTypeString);

      const publicKey = keyPair.publicKey!;
      const publicCryptoKey = await EllipticCurves.exportCryptoKey(publicKey);
      const importedPublicKey =
          await EllipticCurves.importPublicKey('ECDH', publicCryptoKey);
      expect(importedPublicKey).toEqual(publicKey);

      const privateKey = keyPair.privateKey!;
      const privateCryptoKey = await EllipticCurves.exportCryptoKey(privateKey);
      const importedPrivateKey =
          await EllipticCurves.importPrivateKey('ECDH', privateCryptoKey);
      expect(importedPrivateKey).toEqual(privateKey);
    }
  });

  // Test that when ECDSA crypto key is exported and imported it gives the same
  // key as the original one.
  it('import export crypto key e c d s a', async function() {
    const curveTypes = [
      EllipticCurves.CurveType.P256, EllipticCurves.CurveType.P384,
      EllipticCurves.CurveType.P521
    ];
    for (const curve of curveTypes) {
      const curveTypeString = EllipticCurves.curveToString(curve);
      const keyPair =
          await EllipticCurves.generateKeyPair('ECDSA', curveTypeString);

      const publicKey = keyPair.publicKey!;
      const publicCryptoKey = await EllipticCurves.exportCryptoKey(publicKey);
      const importedPublicKey =
          await EllipticCurves.importPublicKey('ECDSA', publicCryptoKey);
      expect(importedPublicKey).toEqual(publicKey);

      const privateKey = keyPair.privateKey!;
      const privateCryptoKey = await EllipticCurves.exportCryptoKey(privateKey);
      const importedPrivateKey =
          await EllipticCurves.importPrivateKey('ECDSA', privateCryptoKey);
      expect(importedPrivateKey).toEqual(privateKey);
    }
  });

  // Test that when JSON ECDH web key is imported and exported it gives the same
  // key as the original one.
  it('import export json key e c d h', async function() {
    for (const testKey of TEST_KEYS) {
      const jwk: JsonWebKey = ({
        'kty': 'EC',
        'crv': testKey.curve,
        'x': Bytes.toBase64(Bytes.fromHex(testKey.x), true),
        'y': Bytes.toBase64(Bytes.fromHex(testKey.y), true),
        'ext': true,
      });

      let importedKey;
      if (!testKey.d) {
        jwk['key_ops'] = [];
        importedKey = await EllipticCurves.importPublicKey('ECDH', jwk);
      } else {
        jwk['key_ops'] = ['deriveKey', 'deriveBits'];
        jwk['d'] = Bytes.toBase64(Bytes.fromHex(testKey.d), true);
        importedKey = await EllipticCurves.importPrivateKey('ECDH', jwk);
      }

      const exportedKey = await EllipticCurves.exportCryptoKey(importedKey);
      expect(exportedKey).toEqual(jwk);
    }
  });

  // Test that when JSON ECDSA web key is imported and exported it gives the
  // same key as the original one.
  it('import export json key e c d s a', async function() {
    for (const testKey of TEST_KEYS) {
      const jwk: JsonWebKey = ({
        'kty': 'EC',
        'crv': testKey.curve,
        'x': Bytes.toBase64(Bytes.fromHex(testKey.x), true),
        'y': Bytes.toBase64(Bytes.fromHex(testKey.y), true),
        'ext': true,
      });

      let importedKey;
      if (!testKey.d) {
        jwk['key_ops'] = ['verify'];
        importedKey = await EllipticCurves.importPublicKey('ECDSA', jwk);
      } else {
        jwk['key_ops'] = ['sign'];
        jwk['d'] = Bytes.toBase64(Bytes.fromHex(testKey.d), true);
        importedKey = await EllipticCurves.importPrivateKey('ECDSA', jwk);
      }

      const exportedKey = await EllipticCurves.exportCryptoKey(importedKey);
      expect(exportedKey).toEqual(jwk);
    }
  });

  it('curve to string', function() {
    expect(EllipticCurves.curveToString(EllipticCurves.CurveType.P256))
        .toBe('P-256');
    expect(EllipticCurves.curveToString(EllipticCurves.CurveType.P384))
        .toBe('P-384');
    expect(EllipticCurves.curveToString(EllipticCurves.CurveType.P521))
        .toBe('P-521');
  });

  it('curve from string', function() {
    expect(EllipticCurves.curveFromString('P-256'))
        .toBe(EllipticCurves.CurveType.P256);
    expect(EllipticCurves.curveFromString('P-384'))
        .toBe(EllipticCurves.CurveType.P384);
    expect(EllipticCurves.curveFromString('P-521'))
        .toBe(EllipticCurves.CurveType.P521);
  });

  it('field size in bytes', function() {
    expect(EllipticCurves.fieldSizeInBytes(EllipticCurves.CurveType.P256))
        .toBe(256 / 8);
    expect(EllipticCurves.fieldSizeInBytes(EllipticCurves.CurveType.P384))
        .toBe(384 / 8);
    expect(EllipticCurves.fieldSizeInBytes(EllipticCurves.CurveType.P521))
        .toBe((521 + 7) / 8);
  });

  it('encoding size in bytes, uncompressed point format type', function() {
    expect(EllipticCurves.encodingSizeInBytes(
               EllipticCurves.CurveType.P256,
               EllipticCurves.PointFormatType.UNCOMPRESSED))
        .toBe(2 * (256 / 8) + 1);
    expect(EllipticCurves.encodingSizeInBytes(
               EllipticCurves.CurveType.P384,
               EllipticCurves.PointFormatType.UNCOMPRESSED))
        .toBe(2 * (384 / 8) + 1);
    expect(EllipticCurves.encodingSizeInBytes(
               EllipticCurves.CurveType.P521,
               EllipticCurves.PointFormatType.UNCOMPRESSED))
        .toBe(2 * ((521 + 7) / 8) + 1);
  });

  it('encoding size in bytes, compressed point format type', function() {
    expect(EllipticCurves.encodingSizeInBytes(
               EllipticCurves.CurveType.P256,
               EllipticCurves.PointFormatType.COMPRESSED))
        .toBe((256 / 8) + 1);
    expect(EllipticCurves.encodingSizeInBytes(
               EllipticCurves.CurveType.P384,
               EllipticCurves.PointFormatType.COMPRESSED))
        .toBe((384 / 8) + 1);
    expect(EllipticCurves.encodingSizeInBytes(
               EllipticCurves.CurveType.P521,
               EllipticCurves.PointFormatType.COMPRESSED))
        .toBe(((521 + 7) / 8) + 1);
  });

  it('encoding size in bytes, crunchy uncompressed point format type',
     function() {
       expect(
           EllipticCurves.encodingSizeInBytes(
               EllipticCurves.CurveType.P256,
               EllipticCurves.PointFormatType.DO_NOT_USE_CRUNCHY_UNCOMPRESSED))
           .toBe(2 * (256 / 8));
       expect(
           EllipticCurves.encodingSizeInBytes(
               EllipticCurves.CurveType.P384,
               EllipticCurves.PointFormatType.DO_NOT_USE_CRUNCHY_UNCOMPRESSED))
           .toBe(2 * (384 / 8));
       expect(
           EllipticCurves.encodingSizeInBytes(
               EllipticCurves.CurveType.P521,
               EllipticCurves.PointFormatType.DO_NOT_USE_CRUNCHY_UNCOMPRESSED))
           .toBe(2 * ((521 + 7) / 8));
     });

  it('point decode, wrong point size', function() {
    const point = new Uint8Array(10);
    const format = EllipticCurves.PointFormatType.UNCOMPRESSED;

    for (const curve
             of [EllipticCurves.CurveType.P256, EllipticCurves.CurveType.P384,
                 EllipticCurves.CurveType.P521]) {
      const curveTypeString = EllipticCurves.curveToString(curve);

      // It should throw an exception as the point array is too short.
      try {
        EllipticCurves.pointDecode(curveTypeString, format, point);
        fail('Should throw an exception.');
        // Preserving old behavior when moving to
        // https://www.typescriptlang.org/tsconfig#useUnknownInCatchVariables
        // tslint:disable-next-line:no-any
      } catch (e: any) {
        expect(e.toString()).toBe('InvalidArgumentsException: invalid point');
      }
    }
  });

  it('point decode, unknown curve', function() {
    const point = new Uint8Array(10);
    const format = EllipticCurves.PointFormatType.UNCOMPRESSED;
    const curve = 'some-unknown-curve';

    try {
      EllipticCurves.pointDecode(curve, format, point);
      fail('Should throw an exception.');
      // Preserving old behavior when moving to
      // https://www.typescriptlang.org/tsconfig#useUnknownInCatchVariables
      // tslint:disable-next-line:no-any
    } catch (e: any) {
      expect(e.toString().includes('unknown curve')).toBe(true);
    }
  });

  it('point encode, compressed', () => {
    for (const test of TEST_VECTORS) {
      const format = EllipticCurves.formatFromString(test.format);
      if (format !== EllipticCurves.PointFormatType.COMPRESSED) {
        // TODO(b/214598739): Investigate compatibility of other formats with
        // Java test vectors.
        continue;
      }
      const point: JsonWebKey = {
        kty: 'EC',
        crv: test.curve,
        x: Bytes.toBase64(
            EllipticCurves.integerToByteArray(BigInt('0x' + test.x)),
            /* websafe = */ true),
        y: Bytes.toBase64(
            EllipticCurves.integerToByteArray(BigInt('0x' + test.y)),
            /* websafe = */ true),
        ext: true,
      };

      const encodedPoint =
          EllipticCurves.pointEncode(assertExists(point.crv), format, point);

      expect(Bytes.toHex(encodedPoint)).toEqual(test.encoded);
    }
  });

  it('point decode, compressed', () => {
    for (const test of TEST_VECTORS) {
      const format = EllipticCurves.formatFromString(test.format);
      if (format !== EllipticCurves.PointFormatType.COMPRESSED) {
        // TODO(b/214598739): Investigate compatibility of other formats with
        // Java test vectors.
        continue;
      }
      const decodedPoint = EllipticCurves.pointDecode(
          test.curve, format, Bytes.fromHex(test.encoded));
      // NOTE: Any leading zero inserted by Bytes.toHex() must be removed.
      const decodedX =
          Bytes.toHex(Bytes.fromBase64(assertExists(decodedPoint.x), true))
              .replace(/^0?/, '');
      const decodedY =
          Bytes.toHex(Bytes.fromBase64(assertExists(decodedPoint.y), true))
              .replace(/^0?/, '');

      expect(decodedX).toEqual(test.x);
      expect(decodedY).toEqual(test.y);
    }
  });

  it('point encode decode', () => {
    for (const test of TEST_VECTORS) {
      const format = EllipticCurves.formatFromString(test.format);
      if (format !== EllipticCurves.PointFormatType.COMPRESSED) {
        // TODO(b/214598739): Investigate compatibility of other formats with
        // Java test vectors.
        continue;
      }
      const point: JsonWebKey = {
        kty: 'EC',
        crv: test.curve,
        x: Bytes.toBase64(
            EllipticCurves.integerToByteArray(BigInt('0x' + test.x)),
            /* websafe = */ true),
        y: Bytes.toBase64(
            EllipticCurves.integerToByteArray(BigInt('0x' + test.y)),
            /* websafe = */ true),
        ext: true,
      };

      const encodedPoint =
          EllipticCurves.pointEncode(assertExists(point.crv), format, point);
      const decodedPoint = EllipticCurves.pointDecode(
          assertExists(point.crv), format, encodedPoint);

      expect(decodedPoint).toEqual(point);
    }
  });

  it('point encode decode, random points', () => {
    for (const format of
             [EllipticCurves.PointFormatType.UNCOMPRESSED,
              EllipticCurves.PointFormatType.DO_NOT_USE_CRUNCHY_UNCOMPRESSED]) {
      for (const curveType
               of [EllipticCurves.CurveType.P256, EllipticCurves.CurveType.P384,
                   EllipticCurves.CurveType.P521]) {
        const curveTypeString = EllipticCurves.curveToString(curveType);
        const x = Random.randBytes(EllipticCurves.fieldSizeInBytes(curveType));
        const y = Random.randBytes(EllipticCurves.fieldSizeInBytes(curveType));
        const point: JsonWebKey = {
          kty: 'EC',
          crv: curveTypeString,
          x: Bytes.toBase64(x, /* websafe = */ true),
          y: Bytes.toBase64(y, /* websafe = */ true),
          ext: true,
        };

        const encodedPoint =
            EllipticCurves.pointEncode(assertExists(point.crv), format, point);
        const decodedPoint =
            EllipticCurves.pointDecode(curveTypeString, format, encodedPoint);

        expect(decodedPoint).toEqual(point);
      }
    }
  });

  it('ecdsa der2 ieee', function() {
    for (const test of ECDSA_IEEE_DER_TEST_VECTORS) {
      expect(EllipticCurves.ecdsaDer2Ieee(test.der, test.ieee.length))
          .toEqual(test.ieee);
    }
  });

  it('ecdsa der2 ieee with invalid signatures', function() {
    for (const test of INVALID_DER_ECDSA_SIGNATURES) {
      try {
        EllipticCurves.ecdsaDer2Ieee(
            Bytes.fromHex(test), 1 /* ieeeLength, ignored */);
        // Preserving old behavior when moving to
        // https://www.typescriptlang.org/tsconfig#useUnknownInCatchVariables
        // tslint:disable-next-line:no-any
      } catch (e: any) {
        expect(e.toString())
            .toBe('InvalidArgumentsException: invalid DER signature');
      }
    }
  });

  it('ecdsa ieee2 der', function() {
    for (const test of ECDSA_IEEE_DER_TEST_VECTORS) {
      expect(EllipticCurves.ecdsaIeee2Der(test.ieee)).toEqual(test.der);
    }
  });

  it('is valid der ecdsa signature', function() {
    for (const test of INVALID_DER_ECDSA_SIGNATURES) {
      expect(EllipticCurves.isValidDerEcdsaSignature(Bytes.fromHex(test)))
          .toBe(false);
    }
  });
});

/**
 * Runs the test with test vector given as an input and returns either empty
 * string or a text describing the failure.
 */
async function runWycheproofTest(test: {
  'tcId': number,
  'public': JsonWebKey,
  'private': JsonWebKey,
  'shared': string,
  'result': string,
}): Promise<string> {
  try {
    const privateKey =
        await EllipticCurves.importPrivateKey('ECDH', test['private']);
    try {
      const publicKey =
          await EllipticCurves.importPublicKey('ECDH', test['public']);
      const sharedSecret =
          await EllipticCurves.computeEcdhSharedSecret(privateKey, publicKey);
      if (test['result'] === 'invalid') {
        return 'Fail on test ' + test['tcId'] + ': No exception thrown.\n';
      }
      const sharedSecretHex = Bytes.toHex(sharedSecret);
      if (sharedSecretHex !== test['shared']) {
        return 'Fail on test ' + test['tcId'] + ': unexpected result was "' +
            sharedSecretHex + '".\n';
      }
      // Preserving old behavior when moving to
      // https://www.typescriptlang.org/tsconfig#useUnknownInCatchVariables
      // tslint:disable-next-line:no-any
    } catch (e: any) {
      if (test['result'] === 'valid') {
        return 'Fail on test ' + test['tcId'] + ': unexpected exception "' +
            e.toString() + '".\n';
      }
    }
    // Preserving old behavior when moving to
    // https://www.typescriptlang.org/tsconfig#useUnknownInCatchVariables
    // tslint:disable-next-line:no-any
  } catch (e: any) {
    if (test['result'] === 'valid') {
      if (test['private']['crv'] == "P-256K") {
        // P-256K doesn't have to be supported. Hence failing to import the
        // key is OK.
        return '';
      }
      return 'Fail on test ' + test['tcId'] +
          ': unexpected exception trying to import private key "' +
          e.toString() + '".\n';
    }
  }
  // If the test passes return an empty string.
  return '';
}

class TestKey {
  constructor(
      readonly curve: string, readonly x: string, readonly y: string,
      readonly d?: string) {}
}

// This set of keys was generated by Java version of Tink.
// It contains one private and one public key for each curve type supported by
// Tink.
const TEST_KEYS: TestKey[] = [
  new TestKey(
      /* curve = */ 'P-256',
      /* x = */
      '2eab800e5d8e9b15d0f87c55324b477ffc9382d7137599e0203113a4e41b50d0',
      /* y = */
      '50bb2c11cfb72f3c380c2f93ea088d6938b91bcf581cd94a73ed0a3f623a6b8b'),
  new TestKey(
      /* curve = */ 'P-256',
      /* x = */
      '844c085cc4450297b681126356e10da074dea817f69bc2b1f3d6b1fc82593c7d',
      /* y = */
      '3cdb41fc89867d2066cc9c4f9ad7e890152bad24de20621abfe608234cbe40f1',
      /* opt_d = */
      'f96796cc28b36038817cc5d7db01c52ee0411dd848dc0833e9e26e989e4a64db'),
  new TestKey(
      /* curve = */ 'P-384',
      /* x = */
      'f3290cc80faa65e8821b0bf835f51e3431a4d78dcebd81b74c53b9b704bd995df93b648d51057a9a96a654fb8332391e',
      /* y = */
      '7e52bb9f654781a6894ef5ae77869207fa32ddbcec4a02d27ba1ead5472b3b9f39b09e9bca7d936809c143e99c655401'),
  new TestKey(
      /* curve = */ 'P-384',
      /* x = */
      'be9df79abedb82fc0e527630955f63f2f74b4984f0a4ac063a089565393ed20ac7a784f4efa434f5b1fa1837c76c8472',
      /* y = */
      'cf34ad0d4f3f2cbd546780509ec7073bb26fa0547d09ed10b83bf9b90903037ac956dbd661d02ce3e397e0547356b331',
      /* opt_d = */
      '34d86595280a8bdca23ccd60eeac9581016e895c2bc867c26dc2f99f6d0f627ce586ad36d1d2981968d8852dc9276d12'),
  new TestKey(
      /* curve = */ 'P-521',
      /* x = */
      '012f2211ec7e634919857be3066becf20c438b84ff24501712c91c98f527b44c7b001f8611935cb1179541c2b3cc3a1fc9259d50cd4842a847ea0cafe22cd75fe788',
      /* y = */
      '016b5d3f5480122643a26ef9e7c7e36875f53c28167d6afc35777d32ea76127d34287325bf14779f2e4cf3864fcc951ba601cec92b03291e34db2e815d4bd6fc2045'),
  new TestKey(
      /* curve = */ 'P-521',
      /* x = */
      '01ee3aabecef323cb4581e044be21914b567c426eae18d71720a71a0b236f5324ef9666fe855f5d7986d3e33a9250396f63c780572b3ad9417d69c2a87773ce39194',
      /* y = */
      '0036bea90db019304719d269e5335f9790e730e241a1b02cfdab8bdcfd0bcff8bdcb3ddeb9c3a94ecff1ab6abb80b0c1655f871c6089d3a4bf8625cf6bd182897f1b',
      /* opt_d = */
      '00b9f9f5d91cbfa9b7f92b041b137ac9822ca4a38f71ce227f624cac6178ca8351fab24bc2cc3f85d7ab72f54a0f9d1bb11a888a79a9c7b1ca267ddc82043585e437')
];

class EcdsaIeeeDerTestVector {
  ieee: Uint8Array;
  der: Uint8Array;

  constructor(ieee: string, der: string) {
    this.ieee = Bytes.fromHex(ieee);
    this.der = Bytes.fromHex(der);
  }
}
const ECDSA_IEEE_DER_TEST_VECTORS: EcdsaIeeeDerTestVector[] = [
  new EcdsaIeeeDerTestVector(  // normal case, short-form length
      '0102030405060708090a0b0c0d0e0f100102030405060708090a0b0c0d0e0f10',
      '302402100102030405060708090a0b0c0d0e0f1002100102030405060708090a0b0c0d0e0f10'),
  new EcdsaIeeeDerTestVector(  // normal case, long-form length
      '010000000100000001000000010000000100000001000000010000000100000001000000010000000100000001000000010000000100000001000000010000000203010000000100000001000000010000000100000001000000010000000100000001000000010000000100000001000000010000000100000001000000010000000203',
      '30818802420100000001000000010000000100000001000000010000000100000001000000010000000100000001000000010000000100000001000000010000000100000002030242010000000100000001000000010000000100000001000000010000000100000001000000010000000100000001000000010000000100000001000000010000000203'),
  new EcdsaIeeeDerTestVector(  // zero prefix.
      '0002030405060708090a0b0c0d0e0f100002030405060708090a0b0c0d0e0f10',
      '3022020f02030405060708090a0b0c0d0e0f10020f02030405060708090a0b0c0d0e0f10'),
  new EcdsaIeeeDerTestVector(  // highest bit is set.
      '00ff030405060708090a0b0c0d0e0f1000ff030405060708090a0b0c0d0e0f10',
      '3024021000ff030405060708090a0b0c0d0e0f10021000ff030405060708090a0b0c0d0e0f10'),
  new EcdsaIeeeDerTestVector(  // highest bit is set, full length.
      'ff02030405060708090a0b0c0d0e0f10ff02030405060708090a0b0c0d0e0f10',
      '3026021100ff02030405060708090a0b0c0d0e0f10021100ff02030405060708090a0b0c0d0e0f10'),
  new EcdsaIeeeDerTestVector(  // all zeros.
      '0000000000000000000000000000000000000000000000000000000000000000',
      '3006020100020100'),
];

const INVALID_DER_ECDSA_SIGNATURES: string[] = [
  '2006020101020101',    // 1st byte is not 0x30 (SEQUENCE tag)
  '3006050101020101',    // 3rd byte is not 0x02 (INTEGER tag)
  '3006020101050101',    // 6th byte is not 0x02 (INTEGER tag)
  '308206020101020101',  // long form length is not 0x81
  '30ff020101020101',    // invalid total length
  '3006020201020101',    // invalid rLength
  '3006020101020201',    // invalid sLength
  '30060201ff020101',    // no extra zero when highest bit of r is set
  '30060201010201ff',    // no extra zero when highest bit of s is set
];

// Following test vectors copied from 'testVectors2' variable in
// /src/test/java/com/google/crypto/tink/subtle/EllipticCurvesTest.java.
class TestVector {
  constructor(
      readonly curve: string, readonly format: string, readonly x: string,
      readonly y: string, readonly encoded: string) {}
}

const TEST_VECTORS:
    TestVector[] =
        [
          new TestVector(
              /* curve = */ 'P-256',
              /* format = */ 'UNCOMPRESSED',
              /* x = */
              'b0cfc7bc02fc980d858077552947ffb449b10df8949dee4e56fe21e016dcb25a',
              /* y = */
              '1886ccdca5487a6772f9401888203f90587cc00a730e2b83d5c6f89b3b568df7',
              /* encoded = */
              '04b0cfc7bc02fc980d858077552947ffb449b10df8949dee4e56fe21e016dcb25a1886ccdca5487a6772f9401888203f90587cc00a730e2b83d5c6f89b3b568df7',
              ),
          new TestVector(
              /* curve = */ 'P-256',
              /* format = */ 'DO_NOT_USE_CRUNCHY_UNCOMPRESSED',
              /* x = */
              'b0cfc7bc02fc980d858077552947ffb449b10df8949dee4e56fe21e016dcb25a',
              /* y = */
              '1886ccdca5487a6772f9401888203f90587cc00a730e2b83d5c6f89b3b568df7',
              /* encoded = */
              'b0cfc7bc02fc980d858077552947ffb449b10df8949dee4e56fe21e016dcb25a1886ccdca5487a6772f9401888203f90587cc00a730e2b83d5c6f89b3b568df7',
              ),
          new TestVector(
              /* curve = */ 'P-256',
              /* format = */ 'COMPRESSED',
              /* x = */
              'b0cfc7bc02fc980d858077552947ffb449b10df8949dee4e56fe21e016dcb25a',
              /* y = */
              '1886ccdca5487a6772f9401888203f90587cc00a730e2b83d5c6f89b3b568df7',
              /* encoded = */
              '03b0cfc7bc02fc980d858077552947ffb449b10df8949dee4e56fe21e016dcb25a',
              ),
          new TestVector(
              /* curve = */ 'P-256',
              /* format = */ 'UNCOMPRESSED',
              /* x = */ '0',
              /* y = */
              '66485c780e2f83d72433bd5d84a06bb6541c2af31dae871728bf856a174f93f4',
              /* encoded = */
              '04000000000000000000000000000000000000000000000000000000000000000066485c780e2f83d72433bd5d84a06bb6541c2af31dae871728bf856a174f93f4',
              ),
          new TestVector(
              /* curve = */ 'P-256',
              /* format = */ 'DO_NOT_USE_CRUNCHY_UNCOMPRESSED',
              /* x = */ '0',
              /* y = */
              '66485c780e2f83d72433bd5d84a06bb6541c2af31dae871728bf856a174f93f4',
              /* encoded = */
              '000000000000000000000000000000000000000000000000000000000000000066485c780e2f83d72433bd5d84a06bb6541c2af31dae871728bf856a174f93f4',
              ),
          new TestVector(
              /* curve = */ 'P-256',
              /* format = */ 'COMPRESSED',
              /* x = */ '0',
              /* y = */
              '66485c780e2f83d72433bd5d84a06bb6541c2af31dae871728bf856a174f93f4',
              /* encoded = */
              '020000000000000000000000000000000000000000000000000000000000000000',
              ),
          new TestVector(
              /* curve = */ 'P-256',
              /* format = */ 'UNCOMPRESSED',
              /* x = */
              'ffffffff00000001000000000000000000000000fffffffffffffffffffffffc',
              /* y = */
              '19719bebf6aea13f25c96dfd7c71f5225d4c8fc09eb5a0ab9f39e9178e55c121',
              /* encoded = */
              '04ffffffff00000001000000000000000000000000fffffffffffffffffffffffc19719bebf6aea13f25c96dfd7c71f5225d4c8fc09eb5a0ab9f39e9178e55c121',
              ),
          new TestVector(
              /* curve = */ 'P-256',
              /* format = */ 'DO_NOT_USE_CRUNCHY_UNCOMPRESSED',
              /* x = */
              'ffffffff00000001000000000000000000000000fffffffffffffffffffffffc',
              /* y = */
              '19719bebf6aea13f25c96dfd7c71f5225d4c8fc09eb5a0ab9f39e9178e55c121',
              /* encoded = */
              'ffffffff00000001000000000000000000000000fffffffffffffffffffffffc19719bebf6aea13f25c96dfd7c71f5225d4c8fc09eb5a0ab9f39e9178e55c121',
              ),
          new TestVector(
              /* curve = */ 'P-256',
              /* format = */ 'COMPRESSED',
              /* x = */
              'ffffffff00000001000000000000000000000000fffffffffffffffffffffffc',
              /* y = */
              '19719bebf6aea13f25c96dfd7c71f5225d4c8fc09eb5a0ab9f39e9178e55c121',
              /* encoded = */
              '03ffffffff00000001000000000000000000000000fffffffffffffffffffffffc',
              ),
          new TestVector(
              /* curve = */ 'P-384',
              /* format = */ 'UNCOMPRESSED',
              /* x = */
              'aa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab7',
              /* y = */
              '3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5f',
              /* encoded = */
              '04aa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab73617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5f',
              ),
          new TestVector(
              /* curve = */ 'P-384',
              /* format = */ 'COMPRESSED',
              /* x = */
              'aa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab7',
              /* y = */
              '3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5f',
              /* encoded = */
              '03aa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab7',
              ),
          new TestVector(
              /* curve = */ 'P-384',
              /* format = */ 'UNCOMPRESSED',
              /* x = */ '0',
              /* y = */
              '3cf99ef04f51a5ea630ba3f9f960dd593a14c9be39fd2bd215d3b4b08aaaf86bbf927f2c46e52ab06fb742b8850e521e',
              /* encoded = */
              '040000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003cf99ef04f51a5ea630ba3f9f960dd593a14c9be39fd2bd215d3b4b08aaaf86bbf927f2c46e52ab06fb742b8850e521e',
              ),
          new TestVector(
              /* curve = */ 'P-384',
              /* format = */ 'COMPRESSED',
              /* x = */ '0',
              /* y = */
              '3cf99ef04f51a5ea630ba3f9f960dd593a14c9be39fd2bd215d3b4b08aaaf86bbf927f2c46e52ab06fb742b8850e521e',
              /* encoded = */
              '02000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000',
              ),
          new TestVector(
              /* curve = */ 'P-384',
              /* format = */ 'UNCOMPRESSED',
              /* x = */ '2',
              /* y = */
              '732152442fb6ee5c3e6ce1d920c059bc623563814d79042b903ce60f1d4487fccd450a86da03f3e6ed525d02017bfdb3',
              /* encoded = */
              '04000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002732152442fb6ee5c3e6ce1d920c059bc623563814d79042b903ce60f1d4487fccd450a86da03f3e6ed525d02017bfdb3',
              ),
          new TestVector(
              /* curve = */ 'P-384',
              /* format = */ 'COMPRESSED',
              /* x = */ '2',
              /* y = */
              '732152442fb6ee5c3e6ce1d920c059bc623563814d79042b903ce60f1d4487fccd450a86da03f3e6ed525d02017bfdb3',
              /* encoded = */
              '03000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002',
              ),
          new TestVector(
              /* curve = */ 'P-384',
              /* format = */ 'UNCOMPRESSED',
              /* x = */
              'fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000fffffffc',
              /* y = */
              '2de9de09a95b74e6b2c430363e1afb8dff7164987a8cfe0a0d5139250ac02f797f81092a9bdc0e09b574a8f43bf80c17',
              /* encoded = */
              '04fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000fffffffc2de9de09a95b74e6b2c430363e1afb8dff7164987a8cfe0a0d5139250ac02f797f81092a9bdc0e09b574a8f43bf80c17',
              ),
          new TestVector(
              /* curve = */ 'P-384',
              /* format = */ 'COMPRESSED',
              /* x = */
              'fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000fffffffc',
              /* y = */
              '2de9de09a95b74e6b2c430363e1afb8dff7164987a8cfe0a0d5139250ac02f797f81092a9bdc0e09b574a8f43bf80c17',
              /* encoded = */
              '03fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000fffffffc',
              ),
          new TestVector(
              /* curve = */ 'P-521',
              /* format = */ 'UNCOMPRESSED',
              /* x = */
              'c6858e06b70404e9cd9e3ecb662395b4429c648139053fb521f828af606b4d3dbaa14b5e77efe75928fe1dc127a2ffa8de3348b3c1856a429bf97e7e31c2e5bd66',
              /* y = */
              '11839296a789a3bc0045c8a5fb42c7d1bd998f54449579b446817afbd17273e662c97ee72995ef42640c550b9013fad0761353c7086a272c24088be94769fd16650',
              /* encoded = */
              '0400c6858e06b70404e9cd9e3ecb662395b4429c648139053fb521f828af606b4d3dbaa14b5e77efe75928fe1dc127a2ffa8de3348b3c1856a429bf97e7e31c2e5bd66011839296a789a3bc0045c8a5fb42c7d1bd998f54449579b446817afbd17273e662c97ee72995ef42640c550b9013fad0761353c7086a272c24088be94769fd16650',
              ),
          new TestVector(
              /* curve = */ 'P-521',
              /* format = */ 'COMPRESSED',
              /* x = */
              'c6858e06b70404e9cd9e3ecb662395b4429c648139053fb521f828af606b4d3dbaa14b5e77efe75928fe1dc127a2ffa8de3348b3c1856a429bf97e7e31c2e5bd66',
              /* y = */
              '11839296a789a3bc0045c8a5fb42c7d1bd998f54449579b446817afbd17273e662c97ee72995ef42640c550b9013fad0761353c7086a272c24088be94769fd16650',
              /* encoded = */
              '0200c6858e06b70404e9cd9e3ecb662395b4429c648139053fb521f828af606b4d3dbaa14b5e77efe75928fe1dc127a2ffa8de3348b3c1856a429bf97e7e31c2e5bd66',
              ),
          new TestVector(
              /* curve = */ 'P-521',
              /* format = */ 'UNCOMPRESSED',
              /* x = */ '0',
              /* y = */
              'd20ec9fea6b577c10d26ca1bb446f40b299e648b1ad508aad068896fee3f8e614bc63054d5772bf01a65d412e0bcaa8e965d2f5d332d7f39f846d440ae001f4f87',
              /* encoded = */
              '0400000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000d20ec9fea6b577c10d26ca1bb446f40b299e648b1ad508aad068896fee3f8e614bc63054d5772bf01a65d412e0bcaa8e965d2f5d332d7f39f846d440ae001f4f87',
              ),
          new TestVector(
              /* curve = */ 'P-521',
              /* format = */ 'COMPRESSED',
              /* x = */ '0',
              /* y = */
              'd20ec9fea6b577c10d26ca1bb446f40b299e648b1ad508aad068896fee3f8e614bc63054d5772bf01a65d412e0bcaa8e965d2f5d332d7f39f846d440ae001f4f87',
              /* encoded = */
              '03000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000',
              ),
          new TestVector(
              /* curve = */ 'P-521',
              /* format = */ 'UNCOMPRESSED',
              /* x = */ '1',
              /* y = */
              '10e59be93c4f269c0269c79e2afd65d6aeaa9b701eacc194fb3ee03df47849bf550ec636ebee0ddd4a16f1cd9406605af38f584567770e3f272d688c832e843564',
              /* encoded = */
              '040000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000010010e59be93c4f269c0269c79e2afd65d6aeaa9b701eacc194fb3ee03df47849bf550ec636ebee0ddd4a16f1cd9406605af38f584567770e3f272d688c832e843564',
              ),
          new TestVector(
              /* curve = */ 'P-521',
              /* format = */ 'COMPRESSED',
              /* x = */ '1',
              /* y = */
              '10e59be93c4f269c0269c79e2afd65d6aeaa9b701eacc194fb3ee03df47849bf550ec636ebee0ddd4a16f1cd9406605af38f584567770e3f272d688c832e843564',
              /* encoded = */
              '02000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001',
              ),
          new TestVector(
              /* curve = */ 'P-521',
              /* format = */ 'UNCOMPRESSED',
              /* x = */ '2',
              /* y = */
              'd9254fdf800496acb33790b103c5ee9fac12832fe546c632225b0f7fce3da4574b1a879b623d722fa8fc34d5fc2a8731aad691a9a8bb8b554c95a051d6aa505acf',
              /* encoded = */
              '0400000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000200d9254fdf800496acb33790b103c5ee9fac12832fe546c632225b0f7fce3da4574b1a879b623d722fa8fc34d5fc2a8731aad691a9a8bb8b554c95a051d6aa505acf',
              ),
          new TestVector(
              /* curve = */ 'P-521',
              /* format = */ 'COMPRESSED',
              /* x = */ '2',
              /* y = */
              'd9254fdf800496acb33790b103c5ee9fac12832fe546c632225b0f7fce3da4574b1a879b623d722fa8fc34d5fc2a8731aad691a9a8bb8b554c95a051d6aa505acf',
              /* encoded = */
              '03000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002',
              ),
          new TestVector(
              /* curve = */ 'P-521',
              /* format = */ 'UNCOMPRESSED',
              /* x = */
              '1fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd',
              /* y = */
              '10e59be93c4f269c0269c79e2afd65d6aeaa9b701eacc194fb3ee03df47849bf550ec636ebee0ddd4a16f1cd9406605af38f584567770e3f272d688c832e843564',
              /* encoded = */
              '0401fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd0010e59be93c4f269c0269c79e2afd65d6aeaa9b701eacc194fb3ee03df47849bf550ec636ebee0ddd4a16f1cd9406605af38f584567770e3f272d688c832e843564',
              ),
          new TestVector(
              /* curve = */ 'P-521',
              /* format = */ 'COMPRESSED',
              /* x = */
              '1fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd',
              /* y = */
              '10e59be93c4f269c0269c79e2afd65d6aeaa9b701eacc194fb3ee03df47849bf550ec636ebee0ddd4a16f1cd9406605af38f584567770e3f272d688c832e843564',
              /* encoded = */
              '0201fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd',
              )
        ];
