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

goog.module('tink.subtle.EncryptThenAuthenticateTest');
goog.setTestOnly('tink.subtle.EncryptThenAuthenticateTest');

const AesCtr = goog.require('tink.subtle.AesCtr');
const Bytes = goog.require('tink.subtle.Bytes');
const EncryptThenAuthenticate = goog.require('tink.subtle.EncryptThenAuthenticate');
const Hmac = goog.require('tink.subtle.Hmac');
const Random = goog.require('tink.subtle.Random');
const array = goog.require('goog.array');
const testSuite = goog.require('goog.testing.testSuite');

testSuite({
  testBasic: function() {
    const cipher = new AesCtr(Random.randBytes(16), 12);
    const tagSize = 10;
    const mac = new Hmac('HMACSHA256', Random.randBytes(16), tagSize);
    const aead = new EncryptThenAuthenticate(cipher, mac, tagSize);
    const results = new Set();
    for (var i = 0; i < 100; i++) {
      const msg = Random.randBytes(20);
      var ciphertext = aead.encrypt(msg);
      assertEquals(Bytes.toHex(msg), Bytes.toHex(aead.decrypt(ciphertext)));
      var aad = null;
      ciphertext = aead.encrypt(msg, aad);
      assertEquals(
          Bytes.toHex(msg), Bytes.toHex(aead.decrypt(ciphertext, aad)));
      aad = Random.randBytes(20);
      ciphertext = aead.encrypt(msg, aad);
      assertEquals(
          Bytes.toHex(msg), Bytes.toHex(aead.decrypt(ciphertext, aad)));
      results.add(Bytes.toHex(ciphertext));
    }
    assertEquals(100, results.size);
  },

  testBitFlipCiphertext: function() {
    const cipher = new AesCtr(Random.randBytes(16), 16);
    const tagSize = 16;
    const mac = new Hmac('HMACSHA256', Random.randBytes(16), tagSize);
    const aead = new EncryptThenAuthenticate(cipher, mac, tagSize);
    const plaintext = Random.randBytes(8);
    const aad = Random.randBytes(8);
    const ciphertext = aead.encrypt(plaintext, aad);
    for (var i = 0; i < ciphertext.length; i++) {
      for (var j = 0; j < 8; j++) {
        const c1 = new Uint8Array(ciphertext);
        c1[i] = (c1[i] ^ (1 << j));
        assertThrows(function() {
          aead.decrypt(c1, aad);
        });
      }
    }
  },

  testBitFlipAad: function() {
    const cipher = new AesCtr(Random.randBytes(16), 16);
    const tagSize = 16;
    const mac = new Hmac('HMACSHA256', Random.randBytes(16), tagSize);
    const aead = new EncryptThenAuthenticate(cipher, mac, tagSize);
    const plaintext = Random.randBytes(8);
    const aad = Random.randBytes(8);
    const ciphertext = aead.encrypt(plaintext, aad);
    for (var i = 0; i < aad.length; i++) {
      for (var j = 0; j < 8; j++) {
        const aad1 = new Uint8Array(aad);
        aad1[i] = (aad1[i] ^ (1 << j));
        assertThrows(function() {
          aead.decrypt(ciphertext, aad1);
        });
      }
    }
  },

  testTruncation: function() {
    const cipher = new AesCtr(Random.randBytes(16), 16);
    const tagSize = 16;
    const mac = new Hmac('HMACSHA256', Random.randBytes(16), tagSize);
    const aead = new EncryptThenAuthenticate(cipher, mac, tagSize);
    const plaintext = Random.randBytes(8);
    const aad = Random.randBytes(8);
    const ciphertext = aead.encrypt(plaintext, aad);
    for (var i = 1; i <= ciphertext.length; i++) {
      const c1 = new Uint8Array(ciphertext.buffer, 0, ciphertext.length - i);
      assertThrows(function() {
        aead.decrypt(c1, aad);
      });
    }
  },

  testWithRfcTestVectors: function() {
    // Test data from
    // https://tools.ietf.org/html/draft-mcgrew-aead-aes-cbc-hmac-sha2-05. As we
    // use CTR while RFC uses CBC mode, it's not possible to compare plaintexts.
    // However, the test is still valueable to make sure that we correcly
    // compute HMAC over ciphertext and aad.
    const RFC_TEST_VECTORS = [
      {
        'macKey': '000102030405060708090a0b0c0d0e0f',
        'encryptionKey': '101112131415161718191a1b1c1d1e1f',
        'ciphertext': '1af38c2dc2b96ffdd86694092341bc04' +
            'c80edfa32ddf39d5ef00c0b468834279' +
            'a2e46a1b8049f792f76bfe54b903a9c9' +
            'a94ac9b47ad2655c5f10f9aef71427e2' +
            'fc6f9b3f399a221489f16362c7032336' +
            '09d45ac69864e3321cf82935ac4096c8' +
            '6e133314c54019e8ca7980dfa4b9cf1b' +
            '384c486f3a54c51078158ee5d79de59f' +
            'bd34d848b3d69550a67646344427ade5' +
            '4b8851ffb598f7f80074b9473c82e2db' +
            '652c3fa36b0a7c5b3219fab3a30bc1c4',
        'aad': '546865207365636f6e64207072696e63' +
            '69706c65206f66204175677573746520' +
            '4b6572636b686f666673',
        'hmacAlgo': 'HMACSHA256',
        'ivSize': 16,
        'tagSize': 16
      },
      {
        'macKey':
            '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f',
        'encryptionKey':
            '202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f',
        'ciphertext': '1af38c2dc2b96ffdd86694092341bc04' +
            '4affaaadb78c31c5da4b1b590d10ffbd' +
            '3dd8d5d302423526912da037ecbcc7bd' +
            '822c301dd67c373bccb584ad3e9279c2' +
            'e6d12a1374b77f077553df829410446b' +
            '36ebd97066296ae6427ea75c2e0846a1' +
            '1a09ccf5370dc80bfecbad28c73f09b3' +
            'a3b75e662a2594410ae496b2e2e6609e' +
            '31e6e02cc837f053d21f37ff4f51950b' +
            'be2638d09dd7a4930930806d0703b1f6' +
            '4dd3b4c088a7f45c216839645b2012bf' +
            '2e6269a8c56a816dbc1b267761955bc5',
        'aad':
            '546865207365636f6e64207072696e6369706c65206f662041756775737465204b6572636b686f666673',
        'hmacAlgo': 'HMACSHA512',
        'ivSize': 16,
        'tagSize': 32
      },
    ];
    array.forEach(RFC_TEST_VECTORS, function(testVector) {
      const hmac = new Hmac(
          testVector.hmacAlgo, Bytes.fromHex(testVector.macKey),
          testVector.tagSize);
      const aesCtr = new AesCtr(
          Bytes.fromHex(testVector.encryptionKey), testVector.ivSize);
      const aead =
          new EncryptThenAuthenticate(aesCtr, hmac, testVector.tagSize);
      const ciphertext = Bytes.fromHex(testVector.ciphertext);
      const aad = Bytes.fromHex(testVector.aad);
      assertNotThrows(function() {
        aead.decrypt(ciphertext, aad);
      });
    });
  },
});
