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

goog.module('tink.signature.EcdsaPublicKeyManager');

const EcdsaUtil = goog.require('tink.signature.EcdsaUtil');
const EcdsaVerify = goog.require('tink.subtle.EcdsaVerify');
const KeyManager = goog.require('tink.KeyManager');
const {PublicKeyVerify} = goog.require('google3.third_party.tink.javascript.signature.internal.public_key_verify');
const {SecurityException} = goog.require('google3.third_party.tink.javascript.exception.security_exception');
const Util = goog.require('tink.Util');
const {PbEcdsaParams, PbEcdsaPublicKey, PbKeyData, PbMessage} = goog.require('google3.third_party.tink.javascript.internal.proto');

/**
 * @implements {KeyManager.KeyFactory}
 * @final
 */
class EcdsaPublicKeyFactory {
  /** @override */
  newKey(keyFormat) {
    throw new SecurityException(
        'This operation is not supported for public keys. ' +
        'Use EcdsaPrivateKeyManager to generate new keys.');
  }

  /** @override */
  newKeyData(serializedKeyFormat) {
    throw new SecurityException(
        'This operation is not supported for public keys. ' +
        'Use EcdsaPrivateKeyManager to generate new keys.');
  }
}


/**
 * @implements {KeyManager.KeyManager<PublicKeyVerify>}
 * @final
 */
class EcdsaPublicKeyManager {
  constructor() {
    this.keyFactory = new EcdsaPublicKeyFactory();
  }

  /** @override */
  async getPrimitive(primitiveType, key) {
    if (primitiveType !== this.getPrimitiveType()) {
      throw new SecurityException(
          'Requested primitive type which is not ' +
          'supported by this key manager.');
    }

    const keyProto = EcdsaPublicKeyManager.getKeyProto_(key);
    EcdsaUtil.validatePublicKey(keyProto, this.getVersion());

    const jwk = EcdsaUtil.getJsonWebKeyFromProto(keyProto);
    const params = /** @type{!PbEcdsaParams} */ (keyProto.getParams());
    const hash = Util.hashTypeProtoToString(params.getHashType());
    const encoding = EcdsaUtil.encodingTypeProtoToEnum(params.getEncoding());
    return await EcdsaVerify.newInstance(jwk, hash, encoding);
  }

  /** @override */
  doesSupport(keyType) {
    return keyType === this.getKeyType();
  }

  /** @override */
  getKeyType() {
    return EcdsaPublicKeyManager.KEY_TYPE;
  }

  /** @override */
  getPrimitiveType() {
    return EcdsaPublicKeyManager.SUPPORTED_PRIMITIVE_;
  }

  /** @override */
  getVersion() {
    return EcdsaPublicKeyManager.VERSION;
  }

  /** @override */
  getKeyFactory() {
    return this.keyFactory;
  }

  /**
   * @private
   * @param {!PbKeyData|!PbMessage} keyMaterial
   * @return {!PbEcdsaPublicKey}
   */
  static getKeyProto_(keyMaterial) {
    if (keyMaterial instanceof PbKeyData) {
      return EcdsaPublicKeyManager.getKeyProtoFromKeyData_(keyMaterial);
    }
    if (keyMaterial instanceof PbEcdsaPublicKey) {
      return keyMaterial;
    }
    throw new SecurityException(
        'Key type is not supported. This key manager supports ' +
        EcdsaPublicKeyManager.KEY_TYPE + '.');
  }

  /**
   * @private
   * @param {!PbKeyData} keyData
   * @return {!PbEcdsaPublicKey}
   */
  static getKeyProtoFromKeyData_(keyData) {
    if (keyData.getTypeUrl() !== EcdsaPublicKeyManager.KEY_TYPE) {
      throw new SecurityException(
          'Key type ' + keyData.getTypeUrl() + ' is not supported. This key ' +
          'manager supports ' + EcdsaPublicKeyManager.KEY_TYPE + '.');
    }

    let /** !PbEcdsaPublicKey */ key;
    try {
      key = PbEcdsaPublicKey.deserializeBinary(keyData.getValue());
    } catch (e) {
      throw new SecurityException(
          'Input cannot be parsed as ' + EcdsaPublicKeyManager.KEY_TYPE +
          ' key-proto.');
    }
    if (!key.getParams() || !key.getX() || !key.getY()) {
      throw new SecurityException(
          'Input cannot be parsed as ' + EcdsaPublicKeyManager.KEY_TYPE +
          ' key-proto.');
    }
    return key;
  }
}

/** @const @public {string} */
EcdsaPublicKeyManager.KEY_TYPE =
    'type.googleapis.com/google.crypto.tink.EcdsaPublicKey';
/** @const @private {!Object} */
EcdsaPublicKeyManager.SUPPORTED_PRIMITIVE_ = PublicKeyVerify;
/** @const @package {number} */
EcdsaPublicKeyManager.VERSION = 0;

exports = EcdsaPublicKeyManager;
