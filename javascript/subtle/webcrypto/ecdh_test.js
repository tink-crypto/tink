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

goog.module('tink.subtle.webcrypto.EcdhTest');
goog.setTestOnly('tink.subtle.webcrypto.EcdhTest');

const Bytes = goog.require('tink.subtle.Bytes');
const Ecdh = goog.require('tink.subtle.webcrypto.Ecdh');
const testSuite = goog.require('goog.testing.testSuite');

testSuite({
  async testComputeSharedSecret() {
    const aliceKeyPair = await Ecdh.generateKeyPair('P-256');
    const bobKeyPair = await Ecdh.generateKeyPair('P-256');
    const sharedSecret1 = await Ecdh.computeSharedSecret(
        aliceKeyPair.privateKey, bobKeyPair.publicKey);
    const sharedSecret2 = await Ecdh.computeSharedSecret(
        bobKeyPair.privateKey, aliceKeyPair.publicKey);
    assertEquals(Bytes.toHex(sharedSecret1), Bytes.toHex(sharedSecret2));
  },
  // TODO(slivova):
  // - add tests for the other functions
  // - add Wycheproof ECDH tests
});
