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

goog.module('tink.aead.exports');

const AeadConfig = goog.require('tink.aead.AeadConfig');
const AeadKeyTemplates = goog.require('tink.aead.AeadKeyTemplates');
const AeadWrapper = goog.require('tink.aead.AeadWrapper');
const AesCtrHmacAeadKeyManager = goog.require('tink.aead.AesCtrHmacAeadKeyManager');
const AesGcmKeyManager = goog.require('tink.aead.AesGcmKeyManager');

goog.exportSymbol('tink.aead.AeadConfig', AeadConfig);
goog.exportProperty(
    AeadKeyTemplates, 'aes128CtrHmacSha256',
    AeadKeyTemplates.aes128CtrHmacSha256);
goog.exportProperty(
    AeadKeyTemplates, 'aes256CtrHmacSha256',
    AeadKeyTemplates.aes256CtrHmacSha256);
goog.exportProperty(AeadKeyTemplates, 'aes128Gcm', AeadKeyTemplates.aes128Gcm);
goog.exportProperty(AeadKeyTemplates, 'aes256Gcm', AeadKeyTemplates.aes256Gcm);
goog.exportProperty(
    AeadKeyTemplates, 'aes256GcmNoPrefix', AeadKeyTemplates.aes256GcmNoPrefix);
goog.exportSymbol('tink.aead.AeadKeyTemplates', AeadKeyTemplates);
goog.exportSymbol('tink.aead.AeadWrapper', AeadWrapper);
goog.exportSymbol(
    'tink.aead.AesCtrHmacAeadKeyManager', AesCtrHmacAeadKeyManager);
goog.exportSymbol('tink.aead.AesGcmKeyManager', AesGcmKeyManager);
