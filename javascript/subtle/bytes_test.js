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

describe('bytes test', function() {
  it('concat', function() {
    let ba1 = new Uint8Array(0);
    let ba2 = new Uint8Array(0);
    let ba3 = new Uint8Array(0);
    let result = Bytes.concat(ba1, ba2, ba3);
    expect(result.length).toBe(0);

    ba1 = Random.randBytes(10);
    result = Bytes.concat(ba1, ba2, ba3);
    expect(result.length).toBe(ba1.length);
    expect(Bytes.toHex(result)).toBe(Bytes.toHex(ba1));

    result = Bytes.concat(ba2, ba1, ba3);
    expect(result.length).toBe(ba1.length);
    expect(Bytes.toHex(result)).toBe(Bytes.toHex(ba1));

    result = Bytes.concat(ba3, ba2, ba1);
    expect(result.length).toBe(ba1.length);
    expect(Bytes.toHex(result)).toBe(Bytes.toHex(ba1));

    ba2 = Random.randBytes(11);
    result = Bytes.concat(ba1, ba2, ba3);
    expect(result.length).toBe(ba1.length + ba2.length);
    expect(Bytes.toHex(result)).toBe(Bytes.toHex(ba1) + Bytes.toHex(ba2));

    result = Bytes.concat(ba1, ba3, ba2);
    expect(result.length).toBe(ba1.length + ba2.length);
    expect(Bytes.toHex(result)).toBe(Bytes.toHex(ba1) + Bytes.toHex(ba2));

    result = Bytes.concat(ba3, ba1, ba2);
    expect(result.length).toBe(ba1.length + ba2.length);
    expect(Bytes.toHex(result)).toBe(Bytes.toHex(ba1) + Bytes.toHex(ba2));

    ba3 = Random.randBytes(12);
    result = Bytes.concat(ba1, ba2, ba3);
    expect(result.length).toBe(ba1.length + ba2.length + ba3.length);
    expect(Bytes.toHex(result))
        .toBe(Bytes.toHex(ba1) + Bytes.toHex(ba2) + Bytes.toHex(ba3));
  });

  it('from number', function() {
    let number = 0;
    expect(Array.from(Bytes.fromNumber(number))).toEqual([
      0, 0, 0, 0, 0, 0, 0, 0
    ]);
    number = 1;
    expect(Array.from(Bytes.fromNumber(number))).toEqual([
      0, 0, 0, 0, 0, 0, 0, 1
    ]);
    number = 4294967296;  // 2^32
    expect(Array.from(Bytes.fromNumber(number))).toEqual([
      0, 0, 0, 1, 0, 0, 0, 0
    ]);
    number = 4294967297;  // 2^32 + 1
    expect(Array.from(Bytes.fromNumber(number))).toEqual([
      0, 0, 0, 1, 0, 0, 0, 1
    ]);
    number = Number.MAX_SAFE_INTEGER; // 2^53 - 1
    expect(Array.from(Bytes.fromNumber(number))).toEqual([
      0, 31, 255, 255, 255, 255, 255, 255
    ]);

    expect(function() {
      Bytes.fromNumber(3.14);
    }).toThrow();
    expect(function() {
      Bytes.fromNumber(-1);
    }).toThrow();
    expect(function() {
      Bytes.fromNumber(Number.MAX_SAFE_INTEGER + 1);
    }).toThrow();
  });

  it('to base64, remove all padding', function() {
    for (let i = 0; i < 10; i++) {
      const array = new Uint8Array(i);
      const base64Representation = Bytes.toBase64(array, true);
      expect(base64Representation[base64Representation.length - 1])
          .not.toBe('=');
    }
  });

  it('to base64, from base64', function() {
    for (let i = 0; i < 100; i++) {
      const array = Random.randBytes(i);
      const base64Representation = Bytes.toBase64(array, true);
      const arrayRepresentation = Bytes.fromBase64(base64Representation, true);
      expect(arrayRepresentation).toEqual(array);
    }
  });

  it('from byte string', function() {
    expect(Bytes.fromByteString(''))
        .withContext('empty string')
        .toEqual(new Uint8Array(0));

    let arr = new Uint8Array(
        [72, 101, 108, 108, 111, 44, 32, 119, 111, 114, 108, 100]);
    expect(Bytes.fromByteString('Hello, world'))
        .withContext('ASCII')
        .toEqual(arr);

    arr = new Uint8Array([83, 99, 104, 246, 110]);
    expect(Bytes.fromByteString('Sch\u00f6n'))
        .withContext('Latin')
        .toEqual(arr);
  });

  it('to byte string', function() {
    expect(Bytes.toByteString(new Uint8Array(0)))
        .withContext('empty string')
        .toBe('');

    let arr = new Uint8Array(
        [72, 101, 108, 108, 111, 44, 32, 119, 111, 114, 108, 100]);
    expect(Bytes.toByteString(arr)).withContext('ASCII').toBe('Hello, world');

    arr = new Uint8Array([83, 99, 104, 246, 110]);
    expect(Bytes.toByteString(arr)).withContext('Latin').toBe('Sch\u00f6n');
  });

  it('to string, from string', function() {
    for (let i = 0; i < 100; i++) {
      const array = Random.randBytes(i);
      const str = Bytes.toByteString(array);
      const arrayRepresentation = Bytes.fromByteString(str);
      expect(arrayRepresentation).toEqual(array);
    }
  });
});
