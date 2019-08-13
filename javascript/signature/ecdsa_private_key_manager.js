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

goog.module('tink.signature.EcdsaPrivateKeyManager');

const Bytes = goog.require('tink.subtle.Bytes');
const EcdsaPublicKeyManager = goog.require('tink.signature.EcdsaPublicKeyManager');
const EcdsaSign = goog.require('tink.subtle.EcdsaSign');
const EcdsaUtil = goog.require('tink.signature.EcdsaUtil');
const EllipticCurves = goog.require('tink.subtle.EllipticCurves');
const KeyManager = goog.require('tink.KeyManager');
const PbEcdsaKeyFormat = goog.require('proto.google.crypto.tink.EcdsaKeyFormat');
const PbEcdsaParams = goog.require('proto.google.crypto.tink.EcdsaParams');
const PbEcdsaPrivateKey = goog.require('proto.google.crypto.tink.EcdsaPrivateKey');
const PbEcdsaPublicKey = goog.require('proto.google.crypto.tink.EcdsaPublicKey');
const PbKeyData = goog.require('proto.google.crypto.tink.KeyData');
const PbMessage = goog.require('jspb.Message');
const PublicKeySign = goog.require('tink.PublicKeySign');
const SecurityException = goog.require('tink.exception.SecurityException');
const Util = goog.require('tink.Util');

/**
 * @implements {KeyManager.PrivateKeyFactory}
 * @final
 */
class EcdsaPrivateKeyFactory {
  /**
   * @override
   * @return {!Promise<!PbEcdsaPrivateKey>}
   */
  async newKey(keyFormat) {
    if (!keyFormat) {
      throw new SecurityException('Key format has to be non-null.');
    }
    const keyFormatProto = EcdsaPrivateKeyFactory.getKeyFormatProto_(keyFormat);
    EcdsaUtil.validateKeyFormat(keyFormatProto);
    return await EcdsaPrivateKeyFactory.newKeyImpl_(keyFormatProto);
  }

  /**
   * @override
   * @return {!Promise<!PbKeyData>}
   */
  async newKeyData(serializedKeyFormat) {
    const key = await this.newKey(serializedKeyFormat);

    const keyData =
        new PbKeyData()
            .setTypeUrl(EcdsaPrivateKeyManager.KEY_TYPE)
            .setValue(key.serializeBinary())
            .setKeyMaterialType(PbKeyData.KeyMaterialType.ASYMMETRIC_PRIVATE);
    return keyData;
  }

  /** @override */
  getPublicKeyData(serializedPrivateKey) {
    const privateKey =
        EcdsaPrivateKeyManager.deserializePrivateKey_(serializedPrivateKey);

    const publicKeyData =
        new PbKeyData()
            .setValue(privateKey.getPublicKey().serializeBinary())
            .setTypeUrl(EcdsaPublicKeyManager.KEY_TYPE)
            .setKeyMaterialType(PbKeyData.KeyMaterialType.ASYMMETRIC_PUBLIC);
    return publicKeyData;
  }

  /**
   * Generates key corresponding to the given key format.
   * WARNING: This function assumes that the keyFormat has been validated.
   *
   * @private
   * @param {!PbEcdsaKeyFormat} keyFormat
   * @return {!Promise<!PbEcdsaPrivateKey>}
   */
  static async newKeyImpl_(keyFormat) {
    const params =
        /** @type {!PbEcdsaParams} */ (keyFormat.getParams());
    const curveTypeProto = params.getCurve();
    const curveTypeSubtle = Util.curveTypeProtoToSubtle(curveTypeProto);
    const curveName = EllipticCurves.curveToString(curveTypeSubtle);
    const keyPair = await EllipticCurves.generateKeyPair('ECDSA', curveName);

    const jsonPublicKey =
        await EllipticCurves.exportCryptoKey(/** @type {?} */ (keyPair).publicKey);
    const jsonPrivateKey =
        await EllipticCurves.exportCryptoKey(/** @type {?} */ (keyPair).privateKey);
    return EcdsaPrivateKeyFactory.jsonToProtoKey_(
        jsonPrivateKey, jsonPublicKey, params);
  }

  /**
   * Creates a private key proto corresponding to given JSON key pair and with
   * the given params.
   *
   * @private
   * @param {!webCrypto.JsonWebKey} jsonPrivateKey
   * @param {!webCrypto.JsonWebKey} jsonPublicKey
   * @param {!PbEcdsaParams} params
   * @return {!PbEcdsaPrivateKey}
   */
  static jsonToProtoKey_(jsonPrivateKey, jsonPublicKey, params) {
    const publicKeyProto =
        new PbEcdsaPublicKey()
            .setVersion(EcdsaPublicKeyManager.VERSION)
            .setParams(params)
            .setX(Bytes.fromBase64(jsonPublicKey['x'], true))
            .setY(Bytes.fromBase64(jsonPublicKey['y'], true));

    const privateKeyProto =
        new PbEcdsaPrivateKey()
            .setVersion(EcdsaPrivateKeyManager.VERSION_)
            .setPublicKey(publicKeyProto)
            .setKeyValue(Bytes.fromBase64(jsonPrivateKey['d'], true));
    return privateKeyProto;
  }

  /**
   * The input keyFormat is either deserialized (in case that the input is
   * Uint8Array) or checked to be an EcdsaKeyFormat-proto (otherwise).
   *
   * @private
   * @param {!PbMessage|!Uint8Array} keyFormat
   * @return {!PbEcdsaKeyFormat}
   */
  static getKeyFormatProto_(keyFormat) {
    if (keyFormat instanceof Uint8Array) {
      return EcdsaPrivateKeyFactory.deserializeKeyFormat_(keyFormat);
    } else {
      if (keyFormat instanceof PbEcdsaKeyFormat) {
        return keyFormat;
      } else {
        throw new SecurityException(
            'Expected ' + EcdsaPrivateKeyManager.KEY_TYPE +
            ' key format proto.');
      }
    }
  }

  /**
   * @private
   * @param {!Uint8Array} keyFormat
   * @return {!PbEcdsaKeyFormat}
   */
  static deserializeKeyFormat_(keyFormat) {
    let /** !PbEcdsaKeyFormat */ keyFormatProto;
    try {
      keyFormatProto = PbEcdsaKeyFormat.deserializeBinary(keyFormat);
    } catch (e) {
      throw new SecurityException(
          'Input cannot be parsed as ' + EcdsaPrivateKeyManager.KEY_TYPE +
          ' key format proto.');
    }
    if (!keyFormatProto.getParams()) {
      throw new SecurityException(
          'Input cannot be parsed as ' + EcdsaPrivateKeyManager.KEY_TYPE +
          ' key format proto.');
    }
    return keyFormatProto;
  }
}


/**
 * @implements {KeyManager.KeyManager<PublicKeySign>}
 * @final
 */
class EcdsaPrivateKeyManager {
  constructor() {
    this.keyFactory = new EcdsaPrivateKeyFactory();
  }

  /** @override */
  async getPrimitive(primitiveType, key) {
    if (primitiveType !== this.getPrimitiveType()) {
      throw new SecurityException(
          'Requested primitive type which is not ' +
          'supported by this key manager.');
    }

    const keyProto = EcdsaPrivateKeyManager.getKeyProto_(key);
    EcdsaUtil.validatePrivateKey(
        keyProto, EcdsaPrivateKeyManager.VERSION_,
        EcdsaPublicKeyManager.VERSION);

    const recepientPrivateKey = EcdsaUtil.getJsonWebKeyFromProto(keyProto);
    const params =
        /** @type {!PbEcdsaParams} */ (keyProto.getPublicKey().getParams());
    const hash = Util.hashTypeProtoToString(params.getHashType());
    const encoding = EcdsaUtil.encodingTypeProtoToEnum(params.getEncoding());
    return await EcdsaSign.newInstance(recepientPrivateKey, hash, encoding);
  }

  /** @override */
  doesSupport(keyType) {
    return keyType === this.getKeyType();
  }

  /** @override */
  getKeyType() {
    return EcdsaPrivateKeyManager.KEY_TYPE;
  }

  /** @override */
  getPrimitiveType() {
    return EcdsaPrivateKeyManager.SUPPORTED_PRIMITIVE_;
  }

  /** @override */
  getVersion() {
    return EcdsaPrivateKeyManager.VERSION_;
  }

  /** @override */
  getKeyFactory() {
    return this.keyFactory;
  }

  /**
   * @private
   * @param {!PbKeyData|!PbMessage} keyMaterial
   * @return {!PbEcdsaPrivateKey}
   */
  static getKeyProto_(keyMaterial) {
    if (keyMaterial instanceof PbKeyData) {
      return EcdsaPrivateKeyManager.getKeyProtoFromKeyData_(keyMaterial);
    }
    if (keyMaterial instanceof PbEcdsaPrivateKey) {
      return keyMaterial;
    }
    throw new SecurityException(
        'Key type is not supported. This key ' +
        'manager supports ' + EcdsaPrivateKeyManager.KEY_TYPE + '.');
  }

  /**
   * @private
   * @param {!PbKeyData} keyData
   * @return {!PbEcdsaPrivateKey}
   */
  static getKeyProtoFromKeyData_(keyData) {
    if (keyData.getTypeUrl() !== EcdsaPrivateKeyManager.KEY_TYPE) {
      throw new SecurityException(
          'Key type ' + keyData.getTypeUrl() +
          ' is not supported. This key manager supports ' +
          EcdsaPrivateKeyManager.KEY_TYPE + '.');
    }
    return EcdsaPrivateKeyManager.deserializePrivateKey_(
        keyData.getValue_asU8());
  }

  /**
   * @private
   * @param {!Uint8Array} serializedPrivateKey
   * @return {!PbEcdsaPrivateKey}
   */
  static deserializePrivateKey_(serializedPrivateKey) {
    let /** !PbEcdsaPrivateKey */ key;
    try {
      key = PbEcdsaPrivateKey.deserializeBinary(serializedPrivateKey);
    } catch (e) {
      throw new SecurityException(
          'Input cannot be parsed as ' + EcdsaPrivateKeyManager.KEY_TYPE +
          ' key-proto.');
    }
    if (!key.getPublicKey() || !key.getKeyValue()) {
      throw new SecurityException(
          'Input cannot be parsed as ' + EcdsaPrivateKeyManager.KEY_TYPE +
          ' key-proto.');
    }
    return key;
  }
}

/** @const @private {!Object} */
EcdsaPrivateKeyManager.SUPPORTED_PRIMITIVE_ = PublicKeySign;
/** @const @public {string} */
EcdsaPrivateKeyManager.KEY_TYPE =
    'type.googleapis.com/google.crypto.tink.EcdsaPrivateKey';
/** @const @private {number} */
EcdsaPrivateKeyManager.VERSION_ = 0;

exports = EcdsaPrivateKeyManager;
