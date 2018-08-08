// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
////////////////////////////////////////////////////////////////////////////////

goog.module('tink.subtle.EllipticCurvesTest');
goog.setTestOnly('tink.subtle.EllipticCurvesTest');

const Bytes = goog.require('tink.subtle.Bytes');
const EllipticCurves = goog.require('tink.subtle.EllipticCurves');
const Random = goog.require('tink.subtle.Random');

const testSuite = goog.require('goog.testing.testSuite');

testSuite({
  testCurveToString() {
    assertEquals(
        'P-256', EllipticCurves.curveToString(EllipticCurves.CurveType.P256));
    assertEquals(
        'P-384', EllipticCurves.curveToString(EllipticCurves.CurveType.P384));
    assertEquals(
        'P-521', EllipticCurves.curveToString(EllipticCurves.CurveType.P521));
  },

  testCurveFromString() {
    assertEquals(
        EllipticCurves.CurveType.P256, EllipticCurves.curveFromString('P-256'));
    assertEquals(
        EllipticCurves.CurveType.P384, EllipticCurves.curveFromString('P-384'));
    assertEquals(
        EllipticCurves.CurveType.P521, EllipticCurves.curveFromString('P-521'));
  },

  testFieldSizeInBytes() {
    assertEquals(
        256 / 8,
        EllipticCurves.fieldSizeInBytes(EllipticCurves.CurveType.P256));
    assertEquals(
        384 / 8,
        EllipticCurves.fieldSizeInBytes(EllipticCurves.CurveType.P384));
    assertEquals(
        (521 + 7) / 8,
        EllipticCurves.fieldSizeInBytes(EllipticCurves.CurveType.P521));
  },

  testEncodingSizeInBytes_uncompressedPointFormatType() {
    assertEquals(
        2 * (256 / 8) + 1,
        EllipticCurves.encodingSizeInBytes(
            EllipticCurves.CurveType.P256,
            EllipticCurves.PointFormatType.UNCOMPRESSED));
    assertEquals(
        2 * (384 / 8) + 1,
        EllipticCurves.encodingSizeInBytes(
            EllipticCurves.CurveType.P384,
            EllipticCurves.PointFormatType.UNCOMPRESSED));
    assertEquals(
        2 * ((521 + 7) / 8) + 1,
        EllipticCurves.encodingSizeInBytes(
            EllipticCurves.CurveType.P521,
            EllipticCurves.PointFormatType.UNCOMPRESSED));
  },

  testEncodingSizeInBytes_compressedPointFormatType() {
    assertEquals(
        (256 / 8) + 1,
        EllipticCurves.encodingSizeInBytes(
            EllipticCurves.CurveType.P256,
            EllipticCurves.PointFormatType.COMPRESSED));
    assertEquals(
        (384 / 8) + 1,
        EllipticCurves.encodingSizeInBytes(
            EllipticCurves.CurveType.P384,
            EllipticCurves.PointFormatType.COMPRESSED));
    assertEquals(
        ((521 + 7) / 8) + 1,
        EllipticCurves.encodingSizeInBytes(
            EllipticCurves.CurveType.P521,
            EllipticCurves.PointFormatType.COMPRESSED));
  },

  testEncodingSizeInBytes_crunchyUncompressedPointFormatType() {
    assertEquals(
        2 * (256 / 8),
        EllipticCurves.encodingSizeInBytes(
            EllipticCurves.CurveType.P256,
            EllipticCurves.PointFormatType.DO_NOT_USE_CRUNCHY_UNCOMPRESSED));
    assertEquals(
        2 * (384 / 8),
        EllipticCurves.encodingSizeInBytes(
            EllipticCurves.CurveType.P384,
            EllipticCurves.PointFormatType.DO_NOT_USE_CRUNCHY_UNCOMPRESSED));
    assertEquals(
        2 * ((521 + 7) / 8),
        EllipticCurves.encodingSizeInBytes(
            EllipticCurves.CurveType.P521,
            EllipticCurves.PointFormatType.DO_NOT_USE_CRUNCHY_UNCOMPRESSED));
  },

  testPointEncode_unknownPointFormat() {
    const format = 10;

    const curveType = EllipticCurves.CurveType.P256;
    const curveTypeString = EllipticCurves.curveToString(curveType);
    const x = Random.randBytes(EllipticCurves.fieldSizeInBytes(curveType));
    const y = Random.randBytes(EllipticCurves.fieldSizeInBytes(curveType));
    const point = /** @type {!webCrypto.JsonWebKey} */ ({
      'kty': 'EC',
      'crv': curveTypeString,
      'x': Bytes.toBase64(x),
      'y': Bytes.toBase64(y),
      'ext': true,
      'key_ops': ['deriveKey', 'deriveBits'],
    });

    try {
      EllipticCurves.pointEncode(point['crv'], format, point);
      fail('Should throw an exception.');
    } catch (e) {
      assertEquals('CustomError: invalid format', e.toString());
    }
  },

  testPointDecode_wrongPointSize() {
    const point = new Uint8Array(10);
    const format = EllipticCurves.PointFormatType.UNCOMPRESSED;

    for (let curve of Object.keys(EllipticCurves.CurveType)) {
      const curveTypeString =
          EllipticCurves.curveToString(EllipticCurves.CurveType[curve]);

      // It should throw an exception as the point array is too short.
      try {
        EllipticCurves.pointDecode(curveTypeString, format, point);
        fail('Should throw an exception.');
      } catch (e) {
        assertEquals('CustomError: invalid point', e.toString());
      }
    }
  },

  testPointDecode_unknownPointFormat() {
    const point = new Uint8Array(10);
    const format = 10;
    const curve = EllipticCurves.curveToString(EllipticCurves.CurveType.P256);

    try {
      EllipticCurves.pointDecode(curve, format, point);
      fail('Should throw an exception.');
    } catch (e) {
      assertEquals('CustomError: invalid format', e.toString());
    }
  },

  testPointDecode_unknownCurve() {
    const point = new Uint8Array(10);
    const format = EllipticCurves.PointFormatType.UNCOMPRESSED;
    const curve = 'some-unknown-curve';

    try {
      EllipticCurves.pointDecode(curve, format, point);
      fail('Should throw an exception.');
    } catch (e) {
      assertTrue(e.toString().includes('unknown curve'));
    }
  },

  testPointEncodeDecode() {
    const format = EllipticCurves.PointFormatType.UNCOMPRESSED;
    for (let curve of Object.keys(EllipticCurves.CurveType)) {
      const curveType = EllipticCurves.CurveType[curve];
      const curveTypeString = EllipticCurves.curveToString(curveType);
      const x = Random.randBytes(EllipticCurves.fieldSizeInBytes(curveType));
      const y = Random.randBytes(EllipticCurves.fieldSizeInBytes(curveType));

      const point = /** @type {!webCrypto.JsonWebKey} */ ({
        'kty': 'EC',
        'crv': curveTypeString,
        'x': Bytes.toBase64(x, /* websafe = */ true),
        'y': Bytes.toBase64(y, /* websafe = */ true),
        'ext': true,
      });

      const encodedPoint =
          EllipticCurves.pointEncode(point['crv'], format, point);
      const decodedPoint =
          EllipticCurves.pointDecode(curveTypeString, format, encodedPoint);

      assertObjectEquals(point, decodedPoint);
    }
  },
});
