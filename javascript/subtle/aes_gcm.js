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

goog.module('tink.subtle.AesGcm');

const Aead = goog.require('tink.Aead');
const AesGcmWebCrypto = goog.require('tink.subtle.webcrypto.AesGcm');
const Environment = goog.require('tink.subtle.Environment');
const UnsupportedException = goog.require('tink.exception.UnsupportedException');
const Validators = goog.require('tink.subtle.Validators');

/**
 * @param {!Uint8Array} key
 * @return {!Promise.<!Aead>}
 * @static
 */
const newInstance = async function(key) {
  Validators.requireUint8Array(key);
  Validators.validateAesKeySize(key.length);

  if (Environment.IS_WEBCRYPTO_AVAILABLE) {
    const cryptoKey = await window.crypto.subtle.importKey(
        'raw' /* format */, key /* keyData */,
        {'name': 'AES-GCM', 'length': key.length} /* algo */,
        false /* extractable*/, ['encrypt', 'decrypt'] /* usage */);
    return new AesGcmWebCrypto(cryptoKey);
  }

  throw new UnsupportedException(
      'Pure Javascript AES-GCM is not supported yet');
};

exports = {newInstance};
