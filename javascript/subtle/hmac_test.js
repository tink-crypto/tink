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

goog.module('tink.subtle.HmacTest');
goog.setTestOnly('tink.subtle.HmacTest');

const Bytes = goog.require('tink.subtle.Bytes');
const Hmac = goog.require('tink.subtle.Hmac');
const Random = goog.require('tink.subtle.Random');
const testSuite = goog.require('goog.testing.testSuite');

testSuite({
  async testBasic() {
    const key = Random.randBytes(16);
    const msg = Random.randBytes(4);
    const hmac = await Hmac.newInstance('SHA-1', key, 10);
    const tag = await hmac.computeMac(msg);
    assertEquals(10, tag.length);
    assertTrue(await hmac.verifyMac(tag, msg));
  },

  async testConstructor() {
    try {
      await Hmac.newInstance(
          'blah', Random.randBytes(16), 16);  // invalid HMAC algo name
      fail('Should throw an exception.');
    } catch (e) {
      assertEquals('CustomError: blah is not supported', e.toString());
    }

    try {
      await Hmac.newInstance(
          'SHA-1', Random.randBytes(15), 16);  // invalid key size
      // TODO(b/115974209): This case does not throw an exception.
    } catch (e) {
      assertEquals(
          'CustomError: key too short, must be at least 16 bytes',
          e.toString());
    }

    try {
      await Hmac.newInstance(
          'SHA-1', Random.randBytes(16), 9);  // tag size too short
      fail('Should throw an exception.');
    } catch (e) {
      assertEquals(
          'CustomError: tag too short, must be at least 10 bytes',
          e.toString());
    }
    try {
      await Hmac.newInstance(
          'SHA-1', Random.randBytes(16), 21);  // tag size too long
      fail('Should throw an exception.');
    } catch (e) {
      assertEquals(
          'CustomError: tag too long, must not be larger than 20 bytes',
          e.toString());
    }

    try {
      await Hmac.newInstance(
          'SHA-256', Random.randBytes(15), 16);  // invalid key size
      // TODO(b/115974209): This case does not throw an exception.
    } catch (e) {
      assertEquals(
          'CustomError: key too short, must be at least 16 bytes',
          e.toString());
    }

    try {
      await Hmac.newInstance(
          'SHA-256', Random.randBytes(16), 9);  // tag size too short
      fail('Should throw an exception.');
    } catch (e) {
      assertEquals(
          'CustomError: tag too short, must be at least 10 bytes',
          e.toString());
    }

    try {
      await Hmac.newInstance(
          'SHA-256', Random.randBytes(16), 33);  // tag size too long
      fail('Should throw an exception.');
    } catch (e) {
      assertEquals(
          'CustomError: tag too long, must not be larger than 32 bytes',
          e.toString());
    }

    try {
      await Hmac.newInstance(
          'SHA-512', Random.randBytes(15), 16);  // invalid key size
      // TODO(b/115974209): This case does not throw an exception.
    } catch (e) {
      assertEquals(
          'CustomError: key too short, must be at least 16 bytes',
          e.toString());
    }

    try {
      await Hmac.newInstance(
          'SHA-512', Random.randBytes(16), 9);  // tag size too short
      fail('Should throw an exception.');
    } catch (e) {
      assertEquals(
          'CustomError: tag too short, must be at least 10 bytes',
          e.toString());
    }

    try {
      await Hmac.newInstance(
          'SHA-512', Random.randBytes(16), 65);  // tag size too long
      fail('Should throw an exception.');
    } catch (e) {
      assertEquals(
          'CustomError: tag too long, must not be larger than 64 bytes',
          e.toString());
    }
  },

  async testConstructor_invalidTagSizes() {
    try {
      await Hmac.newInstance('SHA-512', Random.randBytes(16), NaN);
      fail('Should throw an exception.');
    } catch (e) {
      assertEquals(
          'CustomError: invalid tag size, must be an integer', e.toString());
    }

    try {
      await Hmac.newInstance('SHA-512', Random.randBytes(16), undefined);
      fail('Should throw an exception.');
    } catch (e) {
      assertEquals(
          'CustomError: invalid tag size, must be an integer', e.toString());
    }

    try {
      await Hmac.newInstance('SHA-512', Random.randBytes(16), 12.5);
      fail('Should throw an exception.');
    } catch (e) {
      assertEquals(
          'CustomError: invalid tag size, must be an integer', e.toString());
    }
  },

  async testType() {
    try {
      await Hmac.newInstance('SHA-1', 'blah', 10);
      fail('Should throw an exception.');
    } catch (e) {
      assertEquals(
          'CustomError: input must be a non null Uint8Array', e.toString());
    }
    try {
      await Hmac.newInstance('SHA-1', 123, 10);
      fail('Should throw an exception.');
    } catch (e) {
      assertEquals(
          'CustomError: input must be a non null Uint8Array', e.toString());
    }

    const hmac = await Hmac.newInstance('SHA-1', Random.randBytes(16), 10);
    try {
      await hmac.computeMac('blah');
      fail('Should throw an exception.');
    } catch (e) {
      assertEquals(
          'CustomError: input must be a non null Uint8Array', e.toString());
    }
    try {
      await hmac.computeMac('123');
      fail('Should throw an exception.');
    } catch (e) {
      assertEquals(
          'CustomError: input must be a non null Uint8Array', e.toString());
    }
    try {
      await hmac.verifyMac('blah', Random.randBytes(20));
      fail('Should throw an exception.');
    } catch (e) {
      assertEquals(
          'CustomError: input must be a non null Uint8Array', e.toString());
    }
    try {
      await hmac.verifyMac(123, Random.randBytes(20));
      fail('Should throw an exception.');
    } catch (e) {
      assertEquals(
          'CustomError: input must be a non null Uint8Array', e.toString());
    }
    try {
      await hmac.verifyMac(Random.randBytes(20), 'blah');
      fail('Should throw an exception.');
    } catch (e) {
      assertEquals(
          'CustomError: input must be a non null Uint8Array', e.toString());
    }
    try {
      await hmac.verifyMac(Random.randBytes(20), 123);
      fail('Should throw an exception.');
    } catch (e) {
      assertEquals(
          'CustomError: input must be a non null Uint8Array', e.toString());
    }
  },


  async testModify() {
    const key = Random.randBytes(16);
    const msg = Random.randBytes(8);
    const hmac = await Hmac.newInstance('SHA-1', key, 20);
    const tag = await hmac.computeMac(msg);

    // Modify tag.
    for (let i = 0; i < tag.length; i++) {
      const tag1 = new Uint8Array(tag);
      tag1[i] = tag[i] ^ 0xff;
      assertFalse(await hmac.verifyMac(tag1, msg));
    }

    // Modify msg.
    for (let i = 0; i < msg.length; i++) {
      const msg1 = new Uint8Array(msg);
      msg1[i] = msg1[i] ^ 0xff;
      assertFalse(await hmac.verifyMac(tag, msg1));
    }
  },

  async testWithTestVectors() {
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
      const hmac = await Hmac.newInstance(testVector['algo'], key, tag.length);
      assertTrue(await hmac.verifyMac(tag, message));
    }
  },
});
