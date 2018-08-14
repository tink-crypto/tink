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

goog.module('tink.subtle.EciesAeadHkdfHybridDecrypt');

const EciesAeadHkdfDemHelper = goog.require('tink.subtle.EciesAeadHkdfDemHelper');
const EciesAeadHkdfHybridDecryptWebCrypto = goog.require('tink.subtle.webcrypto.EciesAeadHkdfHybridDecrypt');
const EllipticCurves = goog.require('tink.subtle.EllipticCurves');
const Environment = goog.require('tink.subtle.Environment');
const HybridDecrypt = goog.require('tink.HybridDecrypt');
const SecurityException = goog.require('tink.exception.SecurityException');
const UnsupportedException = goog.require('tink.exception.UnsupportedException');

/**
 * @param {!webCrypto.JsonWebKey} recipientPrivateKey
 * @param {string} hkdfHash the name of the HMAC algorithm, accepted names
 *     are: SHA-1, SHA-256 and SHA-512.
 * @param {EllipticCurves.PointFormatType} pointFormat
 * @param {!EciesAeadHkdfDemHelper} demHelper
 * @param {!Uint8Array=} opt_hkdfSalt
 *
 * @return {!Promise.<!HybridDecrypt>}
 */
const newInstance = async function(
    recipientPrivateKey, hkdfHash, pointFormat, demHelper, opt_hkdfSalt) {
  if (!recipientPrivateKey) {
    throw new SecurityException('Recipient private key has to be non-null.');
  }
  if (!hkdfHash) {
    throw new SecurityException('HKDF hash algorithm has to be non-null.');
  }
  if (!pointFormat) {
    throw new SecurityException('Point format has to be non-null.');
  }
  if (!demHelper) {
    throw new SecurityException('DEM helper has to be non-null.');
  }

  if (Environment.IS_WEBCRYPTO_AVAILABLE) {
    return await EciesAeadHkdfHybridDecryptWebCrypto.newInstance(
        recipientPrivateKey, hkdfHash, pointFormat, demHelper, opt_hkdfSalt);
  }
  throw new UnsupportedException(
      'Pure JavaScript ECIES AEAD HKDF is not supported yet');
};

exports = {newInstance};
