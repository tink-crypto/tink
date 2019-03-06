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

goog.module('tink.subtle.BytesTest');
goog.setTestOnly('tink.subtle.BytesTest');

const Bytes = goog.require('tink.subtle.Bytes');
const Random = goog.require('tink.subtle.Random');
const testSuite = goog.require('goog.testing.testSuite');

testSuite({
  testConcat: function() {
    let ba1 = new Uint8Array(0);
    let ba2 = new Uint8Array(0);
    let ba3 = new Uint8Array(0);
    let result = Bytes.concat(ba1, ba2, ba3);
    assertEquals(0, result.length);

    ba1 = Random.randBytes(10);
    result = Bytes.concat(ba1, ba2, ba3);
    assertEquals(ba1.length, result.length);
    assertEquals(Bytes.toHex(ba1), Bytes.toHex(result));

    result = Bytes.concat(ba2, ba1, ba3);
    assertEquals(ba1.length, result.length);
    assertEquals(Bytes.toHex(ba1), Bytes.toHex(result));

    result = Bytes.concat(ba3, ba2, ba1);
    assertEquals(ba1.length, result.length);
    assertEquals(Bytes.toHex(ba1), Bytes.toHex(result));

    ba2 = Random.randBytes(11);
    result = Bytes.concat(ba1, ba2, ba3);
    assertEquals(ba1.length + ba2.length, result.length);
    assertEquals(Bytes.toHex(ba1) + Bytes.toHex(ba2), Bytes.toHex(result));

    result = Bytes.concat(ba1, ba3, ba2);
    assertEquals(ba1.length + ba2.length, result.length);
    assertEquals(Bytes.toHex(ba1) + Bytes.toHex(ba2), Bytes.toHex(result));

    result = Bytes.concat(ba3, ba1, ba2);
    assertEquals(ba1.length + ba2.length, result.length);
    assertEquals(Bytes.toHex(ba1) + Bytes.toHex(ba2), Bytes.toHex(result));

    ba3 = Random.randBytes(12);
    result = Bytes.concat(ba1, ba2, ba3);
    assertEquals(ba1.length + ba2.length + ba3.length, result.length);
    assertEquals(
        Bytes.toHex(ba1) + Bytes.toHex(ba2) + Bytes.toHex(ba3),
        Bytes.toHex(result));
  },

  testFromNumber: function() {
    let number = 0;
    assertArrayEquals(
        [0, 0, 0, 0, 0, 0, 0, 0], Array.from(Bytes.fromNumber(number)));
    number = 1;
    assertArrayEquals(
        [0, 0, 0, 0, 0, 0, 0, 1], Array.from(Bytes.fromNumber(number)));
    number = 4294967296;  // 2^32
    assertArrayEquals(
        [0, 0, 0, 1, 0, 0, 0, 0], Array.from(Bytes.fromNumber(number)));
    number = 4294967297;  // 2^32 + 1
    assertArrayEquals(
        [0, 0, 0, 1, 0, 0, 0, 1], Array.from(Bytes.fromNumber(number)));
    number = Number.MAX_SAFE_INTEGER; // 2^53 - 1
    assertArrayEquals(
        [0, 31, 255, 255, 255, 255, 255, 255],
        Array.from(Bytes.fromNumber(number)));

    assertThrows(function() {
      Bytes.fromNumber('blah');  // not a number
    });
    assertThrows(function() {
      Bytes.fromNumber(3.14);
    });
    assertThrows(function() {
      Bytes.fromNumber(-1);
    });
    assertThrows(function() {
      Bytes.fromNumber(Number.MAX_SAFE_INTEGER + 1);
    });
  },

  testToBase64_removeAllPadding() {
    for (let i = 0; i < 10; i++) {
      const array = new Uint8Array(i);
      const base64Representation = Bytes.toBase64(array, true);
      assertNotEquals(
          '=', base64Representation[base64Representation.length - 1]);
    }
  },

  testToBase64_fromBase64() {
    for (let i = 0; i < 100; i++) {
      const array = Random.randBytes(i);
      const base64Representation = Bytes.toBase64(array, true);
      const arrayRepresentation = Bytes.fromBase64(base64Representation, true);
      assertObjectEquals(array, arrayRepresentation);
    }
  },

  testFromByteString() {
    assertObjectEquals(
        'empty string', new Uint8Array(), Bytes.fromByteString(''));

    let arr = new Uint8Array(
        [72, 101, 108, 108, 111, 44, 32, 119, 111, 114, 108, 100]);
    assertObjectEquals('ASCII', arr, Bytes.fromByteString('Hello, world'));

    arr = new Uint8Array([83, 99, 104, 246, 110]);
    assertObjectEquals('Latin', arr, Bytes.fromByteString('Sch\u00f6n'));
  },

  testToByteString() {
    assertEquals('empty string', '', Bytes.toByteString(new Uint8Array()));

    let arr = new Uint8Array(
        [72, 101, 108, 108, 111, 44, 32, 119, 111, 114, 108, 100]);
    assertEquals('ASCII', 'Hello, world', Bytes.toByteString(arr));

    arr = new Uint8Array([83, 99, 104, 246, 110]);
    assertEquals('Latin', 'Sch\u00f6n', Bytes.toByteString(arr));
  },

  testToString_fromString() {
    for (let i = 0; i < 100; i++) {
      const array = Random.randBytes(i);
      const str = Bytes.toByteString(array);
      const arrayRepresentation = Bytes.fromByteString(str);
      assertObjectEquals(array, arrayRepresentation);
    }
  },
});
