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

const Hmac = goog.require('tink.subtle.Hmac');
const Random = goog.require('tink.subtle.Random');
const testSuite = goog.require('goog.testing.testSuite');

testSuite({
  testBasic: function() {
    const key = Random.randBytes(16);
    const msg = Random.randBytes(4);
    const hmac = new Hmac('HMACSHA1', key, 20);
    assertNotThrows(function() {
      hmac.verifyMac(hmac.computeMac(msg), msg);
    });
  },

  testModify: function() {
    const key = Random.randBytes(16);
    const msg = Random.randBytes(4);
    const hmac = new Hmac('HMACSHA1', key, 20);
    const tag = hmac.computeMac(msg);

    // Modify tag.
    for (let i = 0; i < tag.length; i++) {
      let v = tag[i] ^ 0xff;
      assertThrows(function() {
        hmac.verifyMac(new Uint8Array(tag).fill(v, i, i + 1), msg);
      });
    }

    // Modify msg.
    for (let i = 0; i < msg.length; i++) {
      let v = msg[i] ^ 0xff;
      assertThrows(function() {
        hmac.verifyMac(tag, new Uint8Array(msg).fill(v, i, i + 1));
      });
    }
  },
});
