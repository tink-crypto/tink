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

goog.module('tink.aead.AeadKeyTemplatesTest');
goog.setTestOnly('tink.aead.AeadKeyTemplatesTest');

const AeadKeyTemplates = goog.require('tink.aead.AeadKeyTemplates');
const PbKeyTemplate = goog.require('proto.google.crypto.tink.KeyTemplate');

const testSuite = goog.require('goog.testing.testSuite');

testSuite({

  testAes128CtrHmacSha256() {
    const keyTemplate = AeadKeyTemplates.aes128CtrHmacSha256();
    assertTrue(keyTemplate instanceof PbKeyTemplate);
  },

  testAes256CtrHmacSha256() {
    const keyTemplate = AeadKeyTemplates.aes256CtrHmacSha256();
    assertTrue(keyTemplate instanceof PbKeyTemplate);
  },

  testAes128Gcm() {
    const keyTemplate = AeadKeyTemplates.aes128Gcm();
    assertTrue(keyTemplate instanceof PbKeyTemplate);
  },

  testAes256Gcm() {
    const keyTemplate = AeadKeyTemplates.aes256Gcm();
    assertTrue(keyTemplate instanceof PbKeyTemplate);
  },

  testAes256GcmNoPrefix() {
    const keyTemplate = AeadKeyTemplates.aes256GcmNoPrefix();
    assertTrue(keyTemplate instanceof PbKeyTemplate);
  }
});
