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
const {PbKeyTemplate} = goog.require('google3.third_party.tink.javascript.internal.proto');

describe('aead key templates test', function() {
  it('aes128 ctr hmac sha256', function() {
    const keyTemplate = AeadKeyTemplates.aes128CtrHmacSha256();
    expect(keyTemplate instanceof PbKeyTemplate).toBe(true);
  });

  it('aes256 ctr hmac sha256', function() {
    const keyTemplate = AeadKeyTemplates.aes256CtrHmacSha256();
    expect(keyTemplate instanceof PbKeyTemplate).toBe(true);
  });

  it('aes128 gcm', function() {
    const keyTemplate = AeadKeyTemplates.aes128Gcm();
    expect(keyTemplate instanceof PbKeyTemplate).toBe(true);
  });

  it('aes256 gcm', function() {
    const keyTemplate = AeadKeyTemplates.aes256Gcm();
    expect(keyTemplate instanceof PbKeyTemplate).toBe(true);
  });

  it('aes256 gcm no prefix', function() {
    const keyTemplate = AeadKeyTemplates.aes256GcmNoPrefix();
    expect(keyTemplate instanceof PbKeyTemplate).toBe(true);
  });
});
