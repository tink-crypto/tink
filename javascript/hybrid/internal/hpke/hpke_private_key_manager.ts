/**
 * @license
 * Copyright 2023 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */

import {SecurityException} from '../../../exception/security_exception';
import * as keyManager from '../../../internal/key_manager';
import {PbHpkeKeyFormat, PbHpkeParams, PbHpkePrivateKey, PbHpkePublicKey, PbKeyData, PbMessage} from '../../../internal/proto';
import {ProtoBytes} from '../../../internal/proto_shims';
import * as util from '../../../internal/util';
import * as bytes from '../../../subtle/bytes';
import * as ellipticCurves from '../../../subtle/elliptic_curves';
import {HybridDecrypt} from '../hybrid_decrypt';

import {HpkeDecrypt} from './hpke_decrypt';
import {HpkePublicKeyManager} from './hpke_public_key_manager';
import * as hpkeUtil from './hpke_util';
import * as hpkeValidators from './hpke_validators';

const VERSION = 0;

/**
 * A container for methods that generate new HPKE key pairs.
 * These methods are separate from the KeyManager as their functionality is
 * independent of the primitive of the corresponding KeyManager.
 * @final
 */
class HpkePrivateKeyFactory implements keyManager.PrivateKeyFactory {
  /**
   * Generates a new random HPKE key according to 'keyFormat'.
   *
   * @param keyFormat is either a KeyFormat
   *     proto or a serialized KeyFormat proto
   * @return the new generated HPKE private key
   */
  async newKey(keyFormat: PbMessage|Uint8Array): Promise<PbHpkePrivateKey> {
    if (!keyFormat) {
      throw new SecurityException('Key format must be non-null.');
    }
    const keyFormatProto: PbHpkeKeyFormat =
        HpkePrivateKeyFactory.getKeyFormatProto(keyFormat);
    hpkeValidators.validateKeyFormat(keyFormatProto);
    const params: PbHpkeParams|undefined = keyFormatProto.getParams();
    if (!params) {
      throw new SecurityException('Params not set');
    }
    const curveType: ellipticCurves.CurveType.P256|
        ellipticCurves.CurveType.P521 =
        hpkeUtil.nistHpkeKemToCurve(params.getKem());
    const curveName = ellipticCurves.curveToString(curveType);
    const keyPair: CryptoKeyPair =
        await ellipticCurves.generateKeyPair('ECDH', curveName);
    const jsonPrivateKey =
        await ellipticCurves.exportCryptoKey(keyPair.privateKey);

    const publicKeyBytes =
        await hpkeUtil.getByteArrayFromPublicKey(keyPair.publicKey);

    const publicKeyProto = (new PbHpkePublicKey())
                               .setVersion(HpkePublicKeyManager.VERSION)
                               .setParams(params)
                               .setPublicKey(publicKeyBytes);

    const {d} = jsonPrivateKey;
    if (d === undefined) {
      throw new SecurityException('d must be set');
    }
    return (new PbHpkePrivateKey())
        .setVersion(VERSION)
        .setPublicKey(publicKeyProto)
        .setPrivateKey(bytes.fromBase64(d, true));
  }

  /**
   * Generates a new random HPKE key based on the "serialized_key_format" and
   * returns it as a KeyData proto.
   */
  async newKeyData(serializedKeyFormat: PbMessage|
                   Uint8Array): Promise<PbKeyData> {
    const key: PbHpkePrivateKey = await this.newKey(serializedKeyFormat);
    const keyData =
        (new PbKeyData())
            .setTypeUrl(HpkePrivateKeyManager.KEY_TYPE)
            .setValue(key.serializeBinary())
            .setKeyMaterialType(PbKeyData.KeyMaterialType.ASYMMETRIC_PRIVATE);
    return keyData;
  }

  /**
   * Returns an HPKE public key data extracted from the given serialized HPKE
   * private key.
   */
  getPublicKeyData(serializedPrivateKey: Uint8Array): PbKeyData {
    const privateKey: PbHpkePrivateKey =
        deserializePrivateKey(serializedPrivateKey);
    const publicKey: PbHpkePublicKey|undefined = privateKey.getPublicKey();
    if (!publicKey) {
      throw new SecurityException('Public key not set');
    }
    const publicKeyData =
        (new PbKeyData())
            .setValue(publicKey.serializeBinary())
            .setTypeUrl(HpkePublicKeyManager.KEY_TYPE)
            .setKeyMaterialType(PbKeyData.KeyMaterialType.ASYMMETRIC_PUBLIC);
    return publicKeyData;
  }

  /**
   * The input keyFormat is either deserialized (in case that the input is
   * Uint8Array) or checked to be an HpkeKeyFormat-proto (otherwise).
   */
  private static getKeyFormatProto(keyFormat: PbMessage|
                                   Uint8Array): PbHpkeKeyFormat {
    if (keyFormat instanceof Uint8Array) {
      return HpkePrivateKeyFactory.deserializeKeyFormat(keyFormat);
    } else if (keyFormat instanceof PbHpkeKeyFormat) {
      return keyFormat;
    } else {
      throw new SecurityException(
          'Expected ' + HpkePrivateKeyManager.KEY_TYPE + ' key format proto.');
    }
  }

  private static deserializeKeyFormat(keyFormat: Uint8Array): PbHpkeKeyFormat {
    let keyFormatProto: PbHpkeKeyFormat;
    try {
      keyFormatProto = PbHpkeKeyFormat.deserializeBinary(keyFormat);
    } catch (e) {
      throw new SecurityException(
          'Input cannot be parsed as ' + HpkePrivateKeyManager.KEY_TYPE +
          ' key format proto.');
    }
    /**
     * Throws the same generic error to avoid discrepancies between different
     * versions.
     */
    if (!keyFormatProto.getParams()) {
      throw new SecurityException(
          'Input cannot be parsed as ' + HpkePrivateKeyManager.KEY_TYPE +
          ' key format proto.');
    }
    return keyFormatProto;
  }
}

/**
 * Key manager that generates new {@link HpkePrivateKey} keys and produces new
 * instances of {@link HpkeDecrypt} primitives.
 *
 * @final
 */
export class HpkePrivateKeyManager implements
    keyManager.KeyManager<HybridDecrypt> {
  private static readonly SUPPORTED_PRIMITIVE = HybridDecrypt;
  static KEY_TYPE = 'type.googleapis.com/google.crypto.tink.HpkePrivateKey';
  keyFactory = new HpkePrivateKeyFactory();
  /**
   * Constructs an instance of the 'HybridDecrypt' primitive for a given HPKE
   * key.
   */
  async getPrimitive(
      primitiveType: util.Constructor<HybridDecrypt>,
      key: PbKeyData|PbMessage): Promise<HybridDecrypt> {
    if (primitiveType !== this.getPrimitiveType()) {
      throw new SecurityException(
          'Requested primitive type which is not ' +
          'supported by this key manager.');
    }
    const keyProto: PbHpkePrivateKey = HpkePrivateKeyManager.getKeyProto(key);
    hpkeValidators.validatePrivateKey(
        keyProto, VERSION, HpkePublicKeyManager.VERSION);
    return HpkeDecrypt.createHpkeDecrypt(keyProto);
  }

  /** Returns true if this KeyManager supports 'HpkePrivateKey' key type. */
  doesSupport(keyType: string) {
    return keyType === this.getKeyType();
  }
  /** Returns the URL which identifies the keys managed by this KeyManager. */
  getKeyType() {
    return HpkePrivateKeyManager.KEY_TYPE;
  }
  /**
   * Returns the type of primitive which can be generated by this KeyManager,
   * i.e. 'HybridDecrypt'
   */
  getPrimitiveType() {
    return HpkePrivateKeyManager.SUPPORTED_PRIMITIVE;
  }

  getVersion() {
    return VERSION;
  }

  getKeyFactory() {
    return this.keyFactory;
  }

  private static getKeyProto(keyMaterial: PbKeyData|
                             PbMessage): PbHpkePrivateKey {
    if (keyMaterial instanceof PbKeyData) {
      return HpkePrivateKeyManager.getKeyProtoFromKeyData(keyMaterial);
    }
    if (keyMaterial instanceof PbHpkePrivateKey) {
      return keyMaterial;
    }
    throw new SecurityException(
        'Key type is not supported. This key ' +
        'manager supports ' + HpkePrivateKeyManager.KEY_TYPE + '.');
  }

  private static getKeyProtoFromKeyData(keyData: PbKeyData): PbHpkePrivateKey {
    if (keyData.getTypeUrl() !== HpkePrivateKeyManager.KEY_TYPE) {
      throw new SecurityException(
          'Key type ' + keyData.getTypeUrl() +
          ' is not supported. This key manager supports ' +
          HpkePrivateKeyManager.KEY_TYPE + '.');
    }
    return deserializePrivateKey(keyData.getValue());
  }
}

/** Returns an HPKE private key instance for the given key serialization */
function deserializePrivateKey(serializedPrivateKey: ProtoBytes):
    PbHpkePrivateKey {
  let key: PbHpkePrivateKey;
  try {
    key = PbHpkePrivateKey.deserializeBinary(serializedPrivateKey);
  } catch (e) {
    throw new SecurityException(
        'Input cannot be parsed as ' + HpkePrivateKeyManager.KEY_TYPE +
        ' key-proto.');
  }
  /**
   * Throws the same generic error to avoid discrepancies between different
   * versions.
   */
  if (!key.getPublicKey() || !key.getPrivateKey()) {
    throw new SecurityException(
        'Input cannot be parsed as ' + HpkePrivateKeyManager.KEY_TYPE +
        ' key-proto.');
  }
  return key;
}
