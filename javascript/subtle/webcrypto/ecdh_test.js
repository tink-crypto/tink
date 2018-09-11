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
const TestCase = goog.require('goog.testing.TestCase');
const testSuite = goog.require('goog.testing.testSuite');


testSuite({
  tearDown() {
    // Reset the promise timeout to default value.
    TestCase.getActiveTestCase().promiseTimeout = 1000;  // 1s
  },

  async testComputeSharedSecret() {
    const aliceKeyPair = await Ecdh.generateKeyPair('P-256');
    const bobKeyPair = await Ecdh.generateKeyPair('P-256');
    const sharedSecret1 = await Ecdh.computeSharedSecret(
        aliceKeyPair.privateKey, bobKeyPair.publicKey);
    const sharedSecret2 = await Ecdh.computeSharedSecret(
        bobKeyPair.privateKey, aliceKeyPair.publicKey);
    assertEquals(Bytes.toHex(sharedSecret1), Bytes.toHex(sharedSecret2));
  },

  async testWycheproof_wycheproofWebcrypto() {
    // Set longer time for promiseTimout as the test sometimes takes longer than
    // 1 second in Firefox.
    TestCase.getActiveTestCase().promiseTimeout = 5000;  // 5s
    await runOnWycheproofTestVectors('ecdh_webcrypto_test.json');
  },
});

/**
 * Runs all test cases from the given file.
 *
 * @param {string} fileName
 */
const runOnWycheproofTestVectors = async function(fileName) {
  const testVectorFile =
      '/google3/third_party/wycheproof/testvectors/' + fileName;
  const content = await (await fetch(testVectorFile)).text();
  const testVector = JSON.parse(content);
  for (let testGroup of testVector['testGroups']) {
    let errors = '';
    for (let test of testGroup['tests']) {
      errors += await runWycheproofTest(test);
    }
    if (errors !== '') {
      fail(errors);
    }
  }
};

/**
 * Runs the test with test vector given as an input and returns either empty
 * string or a text describing the failure.
 *
 * @param {!Object} test - JSON object with test data
 * @return {!Promise<string>}
 */
const runWycheproofTest = async function(test) {
  try {
    const publicKey = await Ecdh.importPublicKey(test['public']);
    const privateKey = await Ecdh.importPrivateKey(test['private']);
    const sharedSecret = await Ecdh.computeSharedSecret(privateKey, publicKey);
    if (test['result'] === 'invalid') {
      return 'Fail on test ' + test['tcId'] + ': No exception thrown.\n';
    }
    const sharedSecretHex = Bytes.toHex(sharedSecret);
    if (sharedSecretHex !== test['shared']) {
      return 'Fail on test ' + test['tcId'] + ': unexpected result was \"' +
          sharedSecretHex + '\".\n';
    }
  } catch (e) {
    if (test['result'] === 'valid') {
      return 'Fail on test ' + test['tcId'] + ': unexpected exception \"' +
          e.toString() + '\".\n';
    }
  }
  // If the test passes return an empty string.
  return '';
};
