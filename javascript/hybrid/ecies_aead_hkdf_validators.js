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

goog.module('tink.hybrid.EciesAeadHkdfValidators');

const AeadConfig = goog.require('tink.aead.AeadConfig');
const {SecurityException} = goog.require('google3.third_party.tink.javascript.exception.security_exception');
const Validators = goog.require('tink.subtle.Validators');
const {PbEciesAeadDemParams, PbEciesAeadHkdfKeyFormat, PbEciesAeadHkdfParams, PbEciesAeadHkdfPrivateKey, PbEciesAeadHkdfPublicKey, PbEciesHkdfKemParams, PbEllipticCurveType, PbHashType, PbPointFormat} = goog.require('google3.third_party.tink.javascript.internal.proto');


/**
 * @private
 * @param {!PbEciesHkdfKemParams} kemParams
 */
const validateKemParams = function(kemParams) {
  const curve = kemParams.getCurveType();
  if (curve !== PbEllipticCurveType.NIST_P256 &&
      curve !== PbEllipticCurveType.NIST_P384 &&
      curve !== PbEllipticCurveType.NIST_P521) {
    throw new SecurityException('Invalid KEM params - unknown curve type.');
  }

  const hashType = kemParams.getHkdfHashType();
  if (hashType !== PbHashType.SHA1 && hashType !== PbHashType.SHA256 &&
      hashType !== PbHashType.SHA384 && hashType !== PbHashType.SHA512) {
    throw new SecurityException('Invalid KEM params - unknown hash type.');
  }
};

/**
 * @private
 * @param {!PbEciesAeadDemParams} demParams
 */
const validateDemParams = function(demParams) {
  if (!demParams.getAeadDem()) {
    throw new SecurityException(
        'Invalid DEM params - missing AEAD key template.');
  }
  // It is checked also here due to methods for creating new keys. We do not
  // allow creating new keys from formats which contains key templates of
  // not supported key types.
  const aeadKeyType = demParams.getAeadDem().getTypeUrl();
  if (aeadKeyType != AeadConfig.AES_CTR_HMAC_AEAD_TYPE_URL &&
      aeadKeyType != AeadConfig.AES_GCM_TYPE_URL) {
    throw new SecurityException(
        'Invalid DEM params - ' + aeadKeyType +
        ' template is not supported by ECIES AEAD HKDF.');
  }
};

/**
 * @package
 * @param {!PbEciesAeadHkdfParams} params
 */
const validateParams = function(params) {
  const kemParams = params.getKemParams();
  if (!kemParams) {
    throw new SecurityException('Invalid params - missing KEM params.');
  }
  validateKemParams(kemParams);

  const demParams = params.getDemParams();
  if (!demParams) {
    throw new SecurityException('Invalid params - missing DEM params.');
  }
  validateDemParams(demParams);

  const pointFormat = params.getEcPointFormat();
  if (pointFormat !== PbPointFormat.UNCOMPRESSED &&
      pointFormat !== PbPointFormat.COMPRESSED &&
      pointFormat !== PbPointFormat.DO_NOT_USE_CRUNCHY_UNCOMPRESSED) {
    throw new SecurityException(
        'Invalid key params - unknown EC point format.');
  }
};

/**
 * @package
 * @param {!PbEciesAeadHkdfKeyFormat} keyFormat
 */
const validateKeyFormat = function(keyFormat) {
  const params = keyFormat.getParams();
  if (!params) {
    throw new SecurityException('Invalid key format - missing key params.');
  }
  validateParams(params);
};

/**
 * @package
 * @param {!PbEciesAeadHkdfPublicKey} key
 * @param {number} publicKeyManagerVersion
 */
const validatePublicKey = function(key, publicKeyManagerVersion) {
  Validators.validateVersion(key.getVersion(), publicKeyManagerVersion);

  const params = key.getParams();

  if (!params) {
    throw new SecurityException('Invalid public key - missing key params.');
  }
  validateParams(params);

  if (!key.getX().length || !key.getY().length) {
    throw new SecurityException(
        'Invalid public key - missing value of X or Y.');
  }

  // TODO Should we add more checks here?
};

/**
 * @package
 * @param {!PbEciesAeadHkdfPrivateKey} key
 * @param {number} privateKeyManagerVersion
 * @param {number} publicKeyManagerVersion
 */
const validatePrivateKey = function(
    key, privateKeyManagerVersion, publicKeyManagerVersion) {
  Validators.validateVersion(key.getVersion(), privateKeyManagerVersion);

  if (!key.getKeyValue()) {
    throw new SecurityException(
        'Invalid private key - missing private key value.');
  }

  const publicKey = key.getPublicKey();
  if (!publicKey) {
    throw new SecurityException(
        'Invalid private key - missing public key information.');
  }
  validatePublicKey(publicKey, publicKeyManagerVersion);

  // TODO Should we add more checks here?
};

exports = {
  validateKeyFormat,
  validateParams,
  validatePublicKey,
  validatePrivateKey,
};
