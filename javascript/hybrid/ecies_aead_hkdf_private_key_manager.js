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

goog.module('tink.hybrid.EciesAeadHkdfPrivateKeyManager');

const Bytes = goog.require('google3.third_party.tink.javascript.subtle.bytes');
const hybridDecrypt = goog.require('google3.third_party.tink.javascript.subtle.ecies_aead_hkdf_hybrid_decrypt');
const EciesAeadHkdfPublicKeyManager = goog.require('tink.hybrid.EciesAeadHkdfPublicKeyManager');
const EciesAeadHkdfUtil = goog.require('tink.hybrid.EciesAeadHkdfUtil');
const EciesAeadHkdfValidators = goog.require('tink.hybrid.EciesAeadHkdfValidators');
const EllipticCurves = goog.require('google3.third_party.tink.javascript.subtle.elliptic_curves');
const {HybridDecrypt} = goog.require('google3.third_party.tink.javascript.hybrid.internal.hybrid_decrypt');
const KeyManager = goog.require('google3.third_party.tink.javascript.internal.key_manager');
const RegistryEciesAeadHkdfDemHelper = goog.require('tink.hybrid.RegistryEciesAeadHkdfDemHelper');
const {SecurityException} = goog.require('google3.third_party.tink.javascript.exception.security_exception');
const Util = goog.require('google3.third_party.tink.javascript.internal.util');
const {PbEciesAeadHkdfKeyFormat, PbEciesAeadHkdfParams, PbEciesAeadHkdfPrivateKey, PbEciesAeadHkdfPublicKey, PbKeyData, PbKeyTemplate, PbMessage} = goog.require('google3.third_party.tink.javascript.internal.proto');

/**
 * @implements {KeyManager.PrivateKeyFactory}
 * @final
 */
class EciesAeadHkdfPrivateKeyFactory {
  /**
   * @override
   * @return {!Promise<!PbEciesAeadHkdfPrivateKey>}
   */
  async newKey(keyFormat) {
    if (!keyFormat) {
      throw new SecurityException('Key format has to be non-null.');
    }
    const keyFormatProto =
        EciesAeadHkdfPrivateKeyFactory.getKeyFormatProto_(keyFormat);
    EciesAeadHkdfValidators.validateKeyFormat(keyFormatProto);
    return await EciesAeadHkdfPrivateKeyFactory.newKeyImpl_(keyFormatProto);
  }

  /**
   * @override
   * @return {!Promise<!PbKeyData>}
   */
  async newKeyData(serializedKeyFormat) {
    const key = await this.newKey(serializedKeyFormat);

    const keyData =
        new PbKeyData()
            .setTypeUrl(EciesAeadHkdfPrivateKeyManager.KEY_TYPE)
            .setValue(key.serializeBinary())
            .setKeyMaterialType(PbKeyData.KeyMaterialType.ASYMMETRIC_PRIVATE);
    return keyData;
  }

  /** @override */
  getPublicKeyData(serializedPrivateKey) {
    const privateKey = EciesAeadHkdfPrivateKeyManager.deserializePrivateKey_(
        serializedPrivateKey);

    const publicKeyData =
        new PbKeyData()
            .setValue(privateKey.getPublicKey().serializeBinary())
            .setTypeUrl(EciesAeadHkdfPublicKeyManager.KEY_TYPE)
            .setKeyMaterialType(PbKeyData.KeyMaterialType.ASYMMETRIC_PUBLIC);
    return publicKeyData;
  }

  /**
   * Generates key corresponding to the given key format.
   * WARNING: This function assume that the keyFormat has been validated.
   *
   * @private
   * @param {!PbEciesAeadHkdfKeyFormat} keyFormat
   * @return {!Promise<!PbEciesAeadHkdfPrivateKey>}
   */
  static async newKeyImpl_(keyFormat) {
    const params =
        /** @type {!PbEciesAeadHkdfParams} */ (keyFormat.getParams());
    const curveTypeProto = params.getKemParams().getCurveType();
    const curveTypeSubtle = Util.curveTypeProtoToSubtle(curveTypeProto);
    const curveName = EllipticCurves.curveToString(curveTypeSubtle);
    const keyPair = await EllipticCurves.generateKeyPair('ECDH', curveName);

    const jsonPublicKey =
        await EllipticCurves.exportCryptoKey(/** @type {?} */ (keyPair).publicKey);
    const jsonPrivateKey =
        await EllipticCurves.exportCryptoKey(/** @type {?} */ (keyPair).privateKey);
    return EciesAeadHkdfPrivateKeyFactory.jsonToProtoKey_(
        jsonPrivateKey, jsonPublicKey, params);
  }

  /**
   * Creates a private key proto corresponding to given JSON key pair and with
   * the given params.
   *
   * @private
   * @param {!webCrypto.JsonWebKey} jsonPrivateKey
   * @param {!webCrypto.JsonWebKey} jsonPublicKey
   * @param {!PbEciesAeadHkdfParams} params
   * @return {!PbEciesAeadHkdfPrivateKey}
   */
  static jsonToProtoKey_(jsonPrivateKey, jsonPublicKey, params) {
    const publicKeyProto =
        new PbEciesAeadHkdfPublicKey()
            .setVersion(EciesAeadHkdfPublicKeyManager.VERSION)
            .setParams(params)
            .setX(Bytes.fromBase64(jsonPublicKey['x'], true))
            .setY(Bytes.fromBase64(jsonPublicKey['y'], true));

    const privateKeyProto =
        new PbEciesAeadHkdfPrivateKey()
            .setVersion(EciesAeadHkdfPrivateKeyManager.VERSION_)
            .setPublicKey(publicKeyProto)
            .setKeyValue(Bytes.fromBase64(jsonPrivateKey['d'], true));
    return privateKeyProto;
  }

  /**
   * The input keyFormat is either deserialized (in case that the input is
   * Uint8Array) or checked to be an EciesAeadHkdfKeyFormat-proto (otherwise).
   *
   * @private
   * @param {!PbMessage|!Uint8Array} keyFormat
   * @return {!PbEciesAeadHkdfKeyFormat}
   */
  static getKeyFormatProto_(keyFormat) {
    if (keyFormat instanceof Uint8Array) {
      return EciesAeadHkdfPrivateKeyFactory.deserializeKeyFormat_(keyFormat);
    } else {
      if (keyFormat instanceof PbEciesAeadHkdfKeyFormat) {
        return keyFormat;
      } else {
        throw new SecurityException(
            'Expected ' + EciesAeadHkdfPrivateKeyManager.KEY_TYPE +
            ' key format proto.');
      }
    }
  }

  /**
   * @private
   * @param {!Uint8Array} keyFormat
   * @return {!PbEciesAeadHkdfKeyFormat}
   */
  static deserializeKeyFormat_(keyFormat) {
    let /** !PbEciesAeadHkdfKeyFormat */ keyFormatProto;
    try {
      keyFormatProto = PbEciesAeadHkdfKeyFormat.deserializeBinary(keyFormat);
    } catch (e) {
      throw new SecurityException(
          'Input cannot be parsed as ' +
          EciesAeadHkdfPrivateKeyManager.KEY_TYPE + ' key format proto.');
    }
    if (!keyFormatProto.getParams()) {
      throw new SecurityException(
          'Input cannot be parsed as ' +
          EciesAeadHkdfPrivateKeyManager.KEY_TYPE + ' key format proto.');
    }
    return keyFormatProto;
  }
}


/**
 * @implements {KeyManager.KeyManager<HybridDecrypt>}
 * @final
 */
class EciesAeadHkdfPrivateKeyManager {
  constructor() {
    this.keyFactory = new EciesAeadHkdfPrivateKeyFactory();
  }

  /** @override */
  async getPrimitive(primitiveType, key) {
    if (primitiveType !== this.getPrimitiveType()) {
      throw new SecurityException(
          'Requested primitive type which is not ' +
          'supported by this key manager.');
    }

    const keyProto = EciesAeadHkdfPrivateKeyManager.getKeyProto_(key);
    EciesAeadHkdfValidators.validatePrivateKey(
        keyProto, EciesAeadHkdfPrivateKeyManager.VERSION_,
        EciesAeadHkdfPublicKeyManager.VERSION);

    const recepientPrivateKey = EciesAeadHkdfUtil.getJsonWebKeyFromProto(keyProto);
    const params = /** @type {!PbEciesAeadHkdfParams} */ (
        keyProto.getPublicKey().getParams());
    const keyTemplate =
        /** @type {!PbKeyTemplate} */ (params.getDemParams().getAeadDem());
    const demHelper = new RegistryEciesAeadHkdfDemHelper(keyTemplate);
    const pointFormat =
        Util.pointFormatProtoToSubtle(params.getEcPointFormat());
    const hkdfHash =
        Util.hashTypeProtoToString(params.getKemParams().getHkdfHashType());
    const hkdfSalt = params.getKemParams().getHkdfSalt_asU8();

    return await hybridDecrypt.fromJsonWebKey(
        recepientPrivateKey, hkdfHash, pointFormat, demHelper, hkdfSalt);
  }

  /** @override */
  doesSupport(keyType) {
    return keyType === this.getKeyType();
  }

  /** @override */
  getKeyType() {
    return EciesAeadHkdfPrivateKeyManager.KEY_TYPE;
  }

  /** @override */
  getPrimitiveType() {
    return EciesAeadHkdfPrivateKeyManager.SUPPORTED_PRIMITIVE_;
  }

  /** @override */
  getVersion() {
    return EciesAeadHkdfPrivateKeyManager.VERSION_;
  }

  /** @override */
  getKeyFactory() {
    return this.keyFactory;
  }

  /**
   * @private
   * @param {!PbKeyData|!PbMessage} keyMaterial
   * @return {!PbEciesAeadHkdfPrivateKey}
   */
  static getKeyProto_(keyMaterial) {
    if (keyMaterial instanceof PbKeyData) {
      return EciesAeadHkdfPrivateKeyManager.getKeyProtoFromKeyData_(
          keyMaterial);
    }
    if (keyMaterial instanceof PbEciesAeadHkdfPrivateKey) {
      return keyMaterial;
    }
    throw new SecurityException(
        'Key type is not supported. This key ' +
        'manager supports ' + EciesAeadHkdfPrivateKeyManager.KEY_TYPE + '.');
  }

  /**
   * @private
   * @param {!PbKeyData} keyData
   * @return {!PbEciesAeadHkdfPrivateKey}
   */
  static getKeyProtoFromKeyData_(keyData) {
    if (keyData.getTypeUrl() !== EciesAeadHkdfPrivateKeyManager.KEY_TYPE) {
      throw new SecurityException(
          'Key type ' + keyData.getTypeUrl() +
          ' is not supported. This key manager supports ' +
          EciesAeadHkdfPrivateKeyManager.KEY_TYPE + '.');
    }
    return EciesAeadHkdfPrivateKeyManager.deserializePrivateKey_(
        keyData.getValue_asU8());
  }

  /**
   * @private
   * @param {!Uint8Array} serializedPrivateKey
   * @return {!PbEciesAeadHkdfPrivateKey}
   */
  static deserializePrivateKey_(serializedPrivateKey) {
    let /** PbEciesAeadHkdfPrivateKey */ key;
    try {
      key = PbEciesAeadHkdfPrivateKey.deserializeBinary(serializedPrivateKey);
    } catch (e) {
      throw new SecurityException(
          'Input cannot be parsed as ' +
          EciesAeadHkdfPrivateKeyManager.KEY_TYPE + ' key-proto.');
    }
    if (!key.getPublicKey() || !key.getKeyValue()) {
      throw new SecurityException(
          'Input cannot be parsed as ' +
          EciesAeadHkdfPrivateKeyManager.KEY_TYPE + ' key-proto.');
    }
    return key;
  }
}

/** @const @private {!Object} */
EciesAeadHkdfPrivateKeyManager.SUPPORTED_PRIMITIVE_ = HybridDecrypt;
/** @const @public {string} */
EciesAeadHkdfPrivateKeyManager.KEY_TYPE =
    'type.googleapis.com/google.crypto.tink.EciesAeadHkdfPrivateKey';
/** @const @private {number} */
EciesAeadHkdfPrivateKeyManager.VERSION_ = 0;

exports = EciesAeadHkdfPrivateKeyManager;
