/**
 * @license
 * Copyright 2020 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */

import {SecurityException} from '../exception/security_exception';
import * as KeyManager from '../internal/key_manager';
import {PbEciesAeadHkdfKeyFormat, PbEciesAeadHkdfParams, PbEciesAeadHkdfPrivateKey, PbEciesAeadHkdfPublicKey, PbKeyData, PbMessage} from '../internal/proto';
import * as Util from '../internal/util';
import * as Bytes from '../subtle/bytes';
import * as eciesAeadHkdfHybridDecrypt from '../subtle/ecies_aead_hkdf_hybrid_decrypt';
import * as EllipticCurves from '../subtle/elliptic_curves';

import {EciesAeadHkdfPublicKeyManager} from './ecies_aead_hkdf_public_key_manager';
import * as EciesAeadHkdfUtil from './ecies_aead_hkdf_util';
import * as EciesAeadHkdfValidators from './ecies_aead_hkdf_validators';
import {HybridDecrypt} from './internal/hybrid_decrypt';
import {RegistryEciesAeadHkdfDemHelper} from './registry_ecies_aead_hkdf_dem_helper';

const VERSION = 0;

/**
 * @final
 */
class EciesAeadHkdfPrivateKeyFactory implements KeyManager.PrivateKeyFactory {
  /**
   */
  async newKey(keyFormat: PbMessage|
               Uint8Array): Promise<PbEciesAeadHkdfPrivateKey> {
    if (!keyFormat) {
      throw new SecurityException('Key format has to be non-null.');
    }
    const keyFormatProto =
        EciesAeadHkdfPrivateKeyFactory.getKeyFormatProto(keyFormat);
    EciesAeadHkdfValidators.validateKeyFormat(keyFormatProto);
    const params = keyFormatProto.getParams();
    if (!params) {
      throw new SecurityException('Params not set');
    }
    const kemParams = params.getKemParams();
    if (!kemParams) {
      throw new SecurityException('KEM params not set');
    }
    const curveTypeProto = kemParams.getCurveType();
    const curveTypeSubtle = Util.curveTypeProtoToSubtle(curveTypeProto);
    const curveName = EllipticCurves.curveToString(curveTypeSubtle);
    const keyPair = await EllipticCurves.generateKeyPair('ECDH', curveName);
    const jsonPublicKey =
        await EllipticCurves.exportCryptoKey(keyPair.publicKey!);
    const jsonPrivateKey =
        await EllipticCurves.exportCryptoKey(keyPair.privateKey!);
    return EciesAeadHkdfPrivateKeyFactory.jsonToProtoKey(
        jsonPrivateKey, jsonPublicKey, params);
  }

  /**
   */
  async newKeyData(serializedKeyFormat: PbMessage|
                   Uint8Array): Promise<PbKeyData> {
    const key = await this.newKey(serializedKeyFormat);
    const keyData =
        (new PbKeyData())
            .setTypeUrl(EciesAeadHkdfPrivateKeyManager.KEY_TYPE)
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
            .setTypeUrl(EciesAeadHkdfPublicKeyManager.KEY_TYPE)
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
      params: PbEciesAeadHkdfParams): PbEciesAeadHkdfPrivateKey {
    const {x, y} = jsonPublicKey;
    if (x === undefined) {
      throw new SecurityException('x must be set');
    }
    if (y === undefined) {
      throw new SecurityException('y must be set');
    }
    const publicKeyProto =
        (new PbEciesAeadHkdfPublicKey())
            .setVersion(EciesAeadHkdfPublicKeyManager.VERSION)
            .setParams(params)
            .setX(Bytes.fromBase64(x, true))
            .setY(Bytes.fromBase64(y, true));
    const {d} = jsonPrivateKey;
    if (d === undefined) {
      throw new SecurityException('d must be set');
    }
    const privateKeyProto = (new PbEciesAeadHkdfPrivateKey())
                                .setVersion(VERSION)
                                .setPublicKey(publicKeyProto)
                                .setKeyValue(Bytes.fromBase64(d, true));
    return privateKeyProto;
  }

  /**
   * The input keyFormat is either deserialized (in case that the input is
   * Uint8Array) or checked to be an EciesAeadHkdfKeyFormat-proto (otherwise).
   *
   */
  private static getKeyFormatProto(keyFormat: PbMessage|
                                   Uint8Array): PbEciesAeadHkdfKeyFormat {
    if (keyFormat instanceof Uint8Array) {
      return EciesAeadHkdfPrivateKeyFactory.deserializeKeyFormat(keyFormat);
    } else if (keyFormat instanceof PbEciesAeadHkdfKeyFormat) {
      return keyFormat;
    } else {
      throw new SecurityException(
          'Expected ' + EciesAeadHkdfPrivateKeyManager.KEY_TYPE +
          ' key format proto.');
    }
  }

  private static deserializeKeyFormat(keyFormat: Uint8Array):
      PbEciesAeadHkdfKeyFormat {
    let keyFormatProto: PbEciesAeadHkdfKeyFormat;
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
 * @final
 */
export class EciesAeadHkdfPrivateKeyManager implements
    KeyManager.KeyManager<HybridDecrypt> {
  private static readonly SUPPORTED_PRIMITIVE = HybridDecrypt;
  static KEY_TYPE: string =
      'type.googleapis.com/google.crypto.tink.EciesAeadHkdfPrivateKey';
  keyFactory = new EciesAeadHkdfPrivateKeyFactory();

  async getPrimitive(
      primitiveType: Util.Constructor<HybridDecrypt>,
      key: PbKeyData|PbMessage) {
    if (primitiveType !== this.getPrimitiveType()) {
      throw new SecurityException(
          'Requested primitive type which is not ' +
          'supported by this key manager.');
    }
    const keyProto = EciesAeadHkdfPrivateKeyManager.getKeyProto(key);
    EciesAeadHkdfValidators.validatePrivateKey(
        keyProto, VERSION, EciesAeadHkdfPublicKeyManager.VERSION);
    const recepientPrivateKey =
        EciesAeadHkdfUtil.getJsonWebKeyFromProto(keyProto);
    const publicKey = keyProto.getPublicKey();
    if (!publicKey) {
      throw new SecurityException('Public key not set');
    }
    const params = publicKey.getParams();
    if (!params) {
      throw new SecurityException('Params not set');
    }
    const demParams = params.getDemParams();
    if (!demParams) {
      throw new SecurityException('DEM params not set');
    }
    const keyTemplate = (demParams.getAeadDem());
    if (!keyTemplate) {
      throw new SecurityException('Key template not set');
    }
    const demHelper = new RegistryEciesAeadHkdfDemHelper(keyTemplate);
    const pointFormat =
        Util.pointFormatProtoToSubtle(params.getEcPointFormat());
    const kemParams = params.getKemParams();
    if (!kemParams) {
      throw new SecurityException('KEM params not set');
    }
    const hkdfHash = Util.hashTypeProtoToString(kemParams.getHkdfHashType());
    const hkdfSalt = kemParams.getHkdfSalt_asU8();
    return eciesAeadHkdfHybridDecrypt.fromJsonWebKey(
        recepientPrivateKey, hkdfHash, pointFormat, demHelper, hkdfSalt);
  }

  doesSupport(keyType: string) {
    return keyType === this.getKeyType();
  }

  getKeyType() {
    return EciesAeadHkdfPrivateKeyManager.KEY_TYPE;
  }

  getPrimitiveType() {
    return EciesAeadHkdfPrivateKeyManager.SUPPORTED_PRIMITIVE;
  }

  getVersion() {
    return VERSION;
  }

  getKeyFactory() {
    return this.keyFactory;
  }

  private static getKeyProto(keyMaterial: PbKeyData|
                             PbMessage): PbEciesAeadHkdfPrivateKey {
    if (keyMaterial instanceof PbKeyData) {
      return EciesAeadHkdfPrivateKeyManager.getKeyProtoFromKeyData(keyMaterial);
    }
    if (keyMaterial instanceof PbEciesAeadHkdfPrivateKey) {
      return keyMaterial;
    }
    throw new SecurityException(
        'Key type is not supported. This key ' +
        'manager supports ' + EciesAeadHkdfPrivateKeyManager.KEY_TYPE + '.');
  }

  private static getKeyProtoFromKeyData(keyData: PbKeyData):
      PbEciesAeadHkdfPrivateKey {
    if (keyData.getTypeUrl() !== EciesAeadHkdfPrivateKeyManager.KEY_TYPE) {
      throw new SecurityException(
          'Key type ' + keyData.getTypeUrl() +
          ' is not supported. This key manager supports ' +
          EciesAeadHkdfPrivateKeyManager.KEY_TYPE + '.');
    }
    return deserializePrivateKey(keyData.getValue_asU8());
  }
}

function deserializePrivateKey(serializedPrivateKey: Uint8Array):
    PbEciesAeadHkdfPrivateKey {
  let key: PbEciesAeadHkdfPrivateKey;
  try {
    key = PbEciesAeadHkdfPrivateKey.deserializeBinary(serializedPrivateKey);
  } catch (e) {
    throw new SecurityException(
        'Input cannot be parsed as ' + EciesAeadHkdfPrivateKeyManager.KEY_TYPE +
        ' key-proto.');
  }
  if (!key.getPublicKey() || !key.getKeyValue_asU8()) {
    throw new SecurityException(
        'Input cannot be parsed as ' + EciesAeadHkdfPrivateKeyManager.KEY_TYPE +
        ' key-proto.');
  }
  return key;
}
