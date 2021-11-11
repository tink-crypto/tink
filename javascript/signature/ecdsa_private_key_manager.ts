/**
 * @license
 * Copyright 2020 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */

import {SecurityException} from '../exception/security_exception';
import * as KeyManager from '../internal/key_manager';
import {PbEcdsaKeyFormat, PbEcdsaParams, PbEcdsaPrivateKey, PbEcdsaPublicKey, PbKeyData, PbMessage} from '../internal/proto';
import * as Util from '../internal/util';
import {Constructor} from '../internal/util';
import * as Bytes from '../subtle/bytes';
import * as ecdsaSign from '../subtle/ecdsa_sign';
import * as EllipticCurves from '../subtle/elliptic_curves';

import {EcdsaPublicKeyManager} from './ecdsa_public_key_manager';
import * as EcdsaUtil from './ecdsa_util';
import {PublicKeySign} from './internal/public_key_sign';

const VERSION = 0;

/**
 * @final
 */
class EcdsaPrivateKeyFactory implements KeyManager.PrivateKeyFactory {
  /**
   */
  async newKey(keyFormat: PbMessage|Uint8Array): Promise<PbEcdsaPrivateKey> {
    if (!keyFormat) {
      throw new SecurityException('Key format has to be non-null.');
    }
    const keyFormatProto = EcdsaPrivateKeyFactory.getKeyFormatProto(keyFormat);
    EcdsaUtil.validateKeyFormat(keyFormatProto);
    const params = keyFormatProto.getParams();
    if (!params) {
      throw new SecurityException('Params not set');
    }
    const curveTypeProto = params.getCurve();
    const curveTypeSubtle = Util.curveTypeProtoToSubtle(curveTypeProto);
    const curveName = EllipticCurves.curveToString(curveTypeSubtle);
    const keyPair = await EllipticCurves.generateKeyPair('ECDSA', curveName);
    const jsonPublicKey =
        await EllipticCurves.exportCryptoKey(keyPair.publicKey!);
    const jsonPrivateKey =
        await EllipticCurves.exportCryptoKey(keyPair.privateKey!);
    return EcdsaPrivateKeyFactory.jsonToProtoKey(
        jsonPrivateKey, jsonPublicKey, params);
  }

  /**
   */
  async newKeyData(serializedKeyFormat: Uint8Array): Promise<PbKeyData> {
    const key = await this.newKey(serializedKeyFormat);
    const keyData =
        (new PbKeyData())
            .setTypeUrl(EcdsaPrivateKeyManager.KEY_TYPE)
            .setValue(key.serializeBinary())
            .setKeyMaterialType(PbKeyData.KeyMaterialType.ASYMMETRIC_PRIVATE);
    return keyData;
  }

  getPublicKeyData(serializedPrivateKey: Uint8Array) {
    const privateKey = deserializePrivateKey(serializedPrivateKey);
    const publicKey = privateKey.getPublicKey();
    if (!publicKey) {
      throw new SecurityException('Public key not set');
    }
    const publicKeyData =
        (new PbKeyData())
            .setValue(publicKey.serializeBinary())
            .setTypeUrl(EcdsaPublicKeyManager.KEY_TYPE)
            .setKeyMaterialType(PbKeyData.KeyMaterialType.ASYMMETRIC_PUBLIC);
    return publicKeyData;
  }

  /**
   * Creates a private key proto corresponding to given JSON key pair and with
   * the given params.
   *
   */
  private static jsonToProtoKey(
      jsonPrivateKey: JsonWebKey, jsonPublicKey: JsonWebKey,
      params: PbEcdsaParams): PbEcdsaPrivateKey {
    const {x, y} = jsonPublicKey;
    if (x === undefined) {
      throw new SecurityException('x must be set');
    }
    if (y === undefined) {
      throw new SecurityException('y must be set');
    }
    const publicKeyProto = (new PbEcdsaPublicKey())
                               .setVersion(EcdsaPublicKeyManager.VERSION)
                               .setParams(params)
                               .setX(Bytes.fromBase64(x, true))
                               .setY(Bytes.fromBase64(y, true));
    const {d} = jsonPrivateKey;
    if (d === undefined) {
      throw new SecurityException('d must be set');
    }
    const privateKeyProto = (new PbEcdsaPrivateKey())
                                .setVersion(VERSION)
                                .setPublicKey(publicKeyProto)
                                .setKeyValue(Bytes.fromBase64(d, true));
    return privateKeyProto;
  }

  /**
   * The input keyFormat is either deserialized (in case that the input is
   * Uint8Array) or checked to be an EcdsaKeyFormat-proto (otherwise).
   *
   */
  private static getKeyFormatProto(keyFormat: PbMessage|
                                   Uint8Array): PbEcdsaKeyFormat {
    if (keyFormat instanceof Uint8Array) {
      return EcdsaPrivateKeyFactory.deserializeKeyFormat(keyFormat);
    } else if (keyFormat instanceof PbEcdsaKeyFormat) {
      return keyFormat;
    } else {
      throw new SecurityException(
          'Expected ' + EcdsaPrivateKeyManager.KEY_TYPE + ' key format proto.');
    }
  }

  private static deserializeKeyFormat(keyFormat: Uint8Array): PbEcdsaKeyFormat {
    let keyFormatProto: PbEcdsaKeyFormat;
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
 * @final
 */
export class EcdsaPrivateKeyManager implements
    KeyManager.KeyManager<PublicKeySign> {
  private static readonly SUPPORTED_PRIMITIVE = PublicKeySign;
  static KEY_TYPE: string =
      'type.googleapis.com/google.crypto.tink.EcdsaPrivateKey';
  keyFactory = new EcdsaPrivateKeyFactory();

  async getPrimitive(
      primitiveType: Constructor<PublicKeySign>, key: PbKeyData|PbMessage) {
    if (primitiveType !== this.getPrimitiveType()) {
      throw new SecurityException(
          'Requested primitive type which is not ' +
          'supported by this key manager.');
    }
    const keyProto = EcdsaPrivateKeyManager.getKeyProto(key);
    EcdsaUtil.validatePrivateKey(
        keyProto, VERSION, EcdsaPublicKeyManager.VERSION);
    const recepientPrivateKey = EcdsaUtil.getJsonWebKeyFromProto(keyProto);
    const publicKey = keyProto.getPublicKey();
    if (!publicKey) {
      throw new SecurityException('Public key not set');
    }
    const params = publicKey.getParams();
    if (!params) {
      throw new SecurityException('Params not set');
    }
    const hash = Util.hashTypeProtoToString(params.getHashType());
    const encoding = EcdsaUtil.encodingTypeProtoToEnum(params.getEncoding());
    return ecdsaSign.fromJsonWebKey(recepientPrivateKey, hash, encoding);
  }

  doesSupport(keyType: string) {
    return keyType === this.getKeyType();
  }

  getKeyType() {
    return EcdsaPrivateKeyManager.KEY_TYPE;
  }

  getPrimitiveType() {
    return EcdsaPrivateKeyManager.SUPPORTED_PRIMITIVE;
  }

  getVersion() {
    return VERSION;
  }

  getKeyFactory() {
    return this.keyFactory;
  }

  private static getKeyProto(keyMaterial: PbKeyData|
                             PbMessage): PbEcdsaPrivateKey {
    if (keyMaterial instanceof PbKeyData) {
      return EcdsaPrivateKeyManager.getKeyProtoFromKeyData(keyMaterial);
    }
    if (keyMaterial instanceof PbEcdsaPrivateKey) {
      return keyMaterial;
    }
    throw new SecurityException(
        'Key type is not supported. This key ' +
        'manager supports ' + EcdsaPrivateKeyManager.KEY_TYPE + '.');
  }

  private static getKeyProtoFromKeyData(keyData: PbKeyData): PbEcdsaPrivateKey {
    if (keyData.getTypeUrl() !== EcdsaPrivateKeyManager.KEY_TYPE) {
      throw new SecurityException(
          'Key type ' + keyData.getTypeUrl() +
          ' is not supported. This key manager supports ' +
          EcdsaPrivateKeyManager.KEY_TYPE + '.');
    }
    return deserializePrivateKey(keyData.getValue_asU8());
  }
}

function deserializePrivateKey(serializedPrivateKey: Uint8Array):
    PbEcdsaPrivateKey {
  let key: PbEcdsaPrivateKey;
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
