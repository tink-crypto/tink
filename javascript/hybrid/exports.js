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

goog.module('tink.hybrid.exports');

const HybridConfig = goog.require('tink.hybrid.HybridConfig');
const HybridDecryptWrapper = goog.require('tink.hybrid.HybridDecryptWrapper');
const HybridEncryptWrapper = goog.require('tink.hybrid.HybridEncryptWrapper');
const HybridKeyTemplates = goog.require('tink.hybrid.HybridKeyTemplates');
const RegistryEciesAeadHkdfDemHelper = goog.require('tink.hybrid.RegistryEciesAeadHkdfDemHelper');

goog.exportSymbol('tink.hybrid.HybridConfig.register', HybridConfig.register);
goog.exportSymbol('tink.hybrid.HybridDecryptWrapper', HybridDecryptWrapper);
goog.exportSymbol('tink.hybrid.HybridEncryptWrapper', HybridEncryptWrapper);
goog.exportProperty(
    HybridKeyTemplates, 'eciesP256HkdfHmacSha256Aes128Gcm',
    HybridKeyTemplates.eciesP256HkdfHmacSha256Aes128Gcm);
goog.exportProperty(
    HybridKeyTemplates, 'eciesP256HkdfHmacSha256Aes128CtrHmacSha256',
    HybridKeyTemplates.eciesP256HkdfHmacSha256Aes128CtrHmacSha256);
goog.exportSymbol('tink.hybrid.HybridKeyTemplates', HybridKeyTemplates);
goog.exportSymbol(
    'tink.hybrid.RegistryEciesAeadHkdfDemHelper',
    RegistryEciesAeadHkdfDemHelper);
