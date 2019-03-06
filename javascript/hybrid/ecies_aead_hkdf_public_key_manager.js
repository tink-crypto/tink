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

goog.module('tink.hybrid.EciesAeadHkdfPublicKeyManager');

const EciesAeadHkdfHybridEncrypt = goog.require('tink.subtle.EciesAeadHkdfHybridEncrypt');
const EciesAeadHkdfUtil = goog.require('tink.hybrid.EciesAeadHkdfUtil');
const EciesAeadHkdfValidators = goog.require('tink.hybrid.EciesAeadHkdfValidators');
const HybridEncrypt = goog.require('tink.HybridEncrypt');
const KeyManager = goog.require('tink.KeyManager');
const PbEciesAeadHkdfParams = goog.require('proto.google.crypto.tink.EciesAeadHkdfParams');
const PbEciesAeadHkdfPublicKey = goog.require('proto.google.crypto.tink.EciesAeadHkdfPublicKey');
const PbKeyData = goog.require('proto.google.crypto.tink.KeyData');
const PbKeyTemplate = goog.require('proto.google.crypto.tink.KeyTemplate');
const PbMessage = goog.require('jspb.Message');
const RegistryEciesAeadHkdfDemHelper = goog.require('tink.hybrid.RegistryEciesAeadHkdfDemHelper');
const SecurityException = goog.require('tink.exception.SecurityException');
const Util = goog.require('tink.Util');

/**
 * @implements {KeyManager.KeyFactory}
 * @final
 */
class EciesAeadHkdfPublicKeyFactory {
  /** @override */
  newKey(keyFormat) {
    throw new SecurityException(
        'This operation is not supported for public keys. ' +
        'Use EciesAeadHkdfPrivateKeyManager to generate new keys.');
  }

  /** @override */
  newKeyData(serializedKeyFormat) {
    throw new SecurityException(
        'This operation is not supported for public keys. ' +
        'Use EciesAeadHkdfPrivateKeyManager to generate new keys.');
  }
}


/**
 * @implements {KeyManager.KeyManager<HybridEncrypt>}
 * @final
 */
class EciesAeadHkdfPublicKeyManager {
  constructor() {
    this.keyFactory = new EciesAeadHkdfPublicKeyFactory();
  }

  /** @override */
  async getPrimitive(primitiveType, key) {
    if (primitiveType !== this.getPrimitiveType()) {
      throw new SecurityException(
          'Requested primitive type which is not ' +
          'supported by this key manager.');
    }

    const keyProto = EciesAeadHkdfPublicKeyManager.getKeyProto_(key);
    EciesAeadHkdfValidators.validatePublicKey(keyProto, this.getVersion());

    const recepientPublicKey = EciesAeadHkdfUtil.getJsonWebKeyFromProto(keyProto);
    const params = /** @type{!PbEciesAeadHkdfParams} */ (keyProto.getParams());
    const keyTemplate =
        /** @type {!PbKeyTemplate} */ (params.getDemParams().getAeadDem());
    const demHelper = new RegistryEciesAeadHkdfDemHelper(keyTemplate);
    const pointFormat =
        Util.pointFormatProtoToSubtle(params.getEcPointFormat());
    const hkdfHash =
        Util.hashTypeProtoToString(params.getKemParams().getHkdfHashType());
    const hkdfSalt = params.getKemParams().getHkdfSalt_asU8();

    return await EciesAeadHkdfHybridEncrypt.newInstance(
        recepientPublicKey, hkdfHash, pointFormat, demHelper, hkdfSalt);
  }

  /** @override */
  doesSupport(keyType) {
    return keyType === this.getKeyType();
  }

  /** @override */
  getKeyType() {
    return EciesAeadHkdfPublicKeyManager.KEY_TYPE;
  }

  /** @override */
  getPrimitiveType() {
    return EciesAeadHkdfPublicKeyManager.SUPPORTED_PRIMITIVE_;
  }

  /** @override */
  getVersion() {
    return EciesAeadHkdfPublicKeyManager.VERSION;
  }

  /** @override */
  getKeyFactory() {
    return this.keyFactory;
  }

  /**
   * @private
   * @param {!PbKeyData|!PbMessage} keyMaterial
   * @return {!PbEciesAeadHkdfPublicKey}
   */
  static getKeyProto_(keyMaterial) {
    if (keyMaterial instanceof PbKeyData) {
      return EciesAeadHkdfPublicKeyManager.getKeyProtoFromKeyData_(keyMaterial);
    }
    if (keyMaterial instanceof PbEciesAeadHkdfPublicKey) {
      return keyMaterial;
    }
    throw new SecurityException(
        'Key type is not supported. This key manager supports ' +
        EciesAeadHkdfPublicKeyManager.KEY_TYPE + '.');
  }

  /**
   * @private
   * @param {!PbKeyData} keyData
   * @return {!PbEciesAeadHkdfPublicKey}
   */
  static getKeyProtoFromKeyData_(keyData) {
    if (keyData.getTypeUrl() !== EciesAeadHkdfPublicKeyManager.KEY_TYPE) {
      throw new SecurityException(
          'Key type ' + keyData.getTypeUrl() + ' is not supported. This key ' +
          'manager supports ' + EciesAeadHkdfPublicKeyManager.KEY_TYPE + '.');
    }

    let /** PbEciesAeadHkdfPublicKey */ key;
    try {
      key = PbEciesAeadHkdfPublicKey.deserializeBinary(keyData.getValue());
    } catch (e) {
      throw new SecurityException(
          'Input cannot be parsed as ' +
          EciesAeadHkdfPublicKeyManager.KEY_TYPE + ' key-proto.');
    }
    if (!key.getParams() || !key.getX() || !key.getY()) {
      throw new SecurityException(
          'Input cannot be parsed as ' +
          EciesAeadHkdfPublicKeyManager.KEY_TYPE + ' key-proto.');
    }
    return key;
  }
}

/** @const @public {string} */
EciesAeadHkdfPublicKeyManager.KEY_TYPE =
    'type.googleapis.com/google.crypto.tink.EciesAeadHkdfPublicKey';
/** @const @private {!Object} */
EciesAeadHkdfPublicKeyManager.SUPPORTED_PRIMITIVE_ = HybridEncrypt;
/** @const @package {number} */
EciesAeadHkdfPublicKeyManager.VERSION = 0;

exports = EciesAeadHkdfPublicKeyManager;
