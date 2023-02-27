/**
 * @license
 * Copyright 2023 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */

import {InvalidArgumentsException} from '../../../exception/invalid_arguments_exception';
import {SecurityException} from '../../../exception/security_exception';
import {PbHpkeKem, PbHpkeParams, PbHpkePrivateKey, PbHpkePublicKey} from '../../../internal/proto';
import {bytesAsU8} from '../../../internal/proto_shims';
import {HybridDecrypt} from '../hybrid_decrypt';

import {HpkeAead} from './hpke_aead';
import * as hpkeContext from './hpke_context';
import {HpkeKdf} from './hpke_kdf';
import {HpkeKem} from './hpke_kem';
import {HpkeKemKeyFactory} from './hpke_kem_key_factory';
import {HpkeKemPrivateKey} from './hpke_kem_private_key';
import {HpkePrimitiveFactory} from './hpke_primitive_factory';

/**
 * Hybrid Public Key Encryption (HPKE) decryption.
 *
 * @final
 */
export class HpkeDecrypt extends HybridDecrypt {
  private static readonly EMPTY_ASSOCIATED_DATA = new Uint8Array(0);

  private readonly recipientPrivateKey: HpkeKemPrivateKey;
  private readonly kem: HpkeKem;
  private readonly kdf: HpkeKdf;
  private readonly aead: HpkeAead;
  private readonly encapsulatedKeyLength: number;

  constructor(
      recipientPrivateKey: HpkeKemPrivateKey, kem: HpkeKem, kdf: HpkeKdf,
      aead: HpkeAead, encapsulatedKeyLength: number) {
    super();
    if (!recipientPrivateKey) {
      throw new InvalidArgumentsException(
          'Recipient private key must be non-null.');
    }
    if (!kem) {
      throw new InvalidArgumentsException('KEM algorithm must be non-null.');
    }
    if (!kdf) {
      throw new InvalidArgumentsException('KDF algorithm must be non-null.');
    }
    if (!aead) {
      throw new InvalidArgumentsException('AEAD algorithm must be non-null.');
    }

    this.recipientPrivateKey = recipientPrivateKey;
    this.kem = kem;
    this.kdf = kdf;
    this.aead = aead;
    this.encapsulatedKeyLength = encapsulatedKeyLength;
  }

  /**
   * Returns the encapsulated key length (in bytes) for the specified
   * `kemProtoEnum`. This value corresponds to the 'Nenc' column in the following
   * table.
   *
   * <p>https://www.rfc-editor.org/rfc/rfc9180.html#name-key-encapsulation-mechanism.
   */
  private static encodingSizeInBytes(kemProtoEnum: PbHpkeKem) {
    switch (kemProtoEnum) {
      case PbHpkeKem.DHKEM_P256_HKDF_SHA256:
        return 65;
      case PbHpkeKem.DHKEM_P521_HKDF_SHA512:
        return 133;
      default:
        throw new InvalidArgumentsException(
            'Unable to determine KEM-encoding length');
    }
  }

  /**
   * Returns an HPKE decryption primitive created from a given
   * recipientPrivateKey.
   */
  static async createHpkeDecrypt(recipientPrivateKey: PbHpkePrivateKey) {
    if (bytesAsU8(recipientPrivateKey.getPrivateKey()).length === 0) {
      throw new InvalidArgumentsException('Recipient private key is empty.');
    }
    const publicKey: PbHpkePublicKey|undefined =
        recipientPrivateKey.getPublicKey();
    if (!publicKey) {
      throw new InvalidArgumentsException(
          'Recipient private key is missing public key field.');
    }
    const params: PbHpkeParams|undefined = publicKey.getParams();
    if (!params) {
      throw new InvalidArgumentsException(
          'Public key is missing params field.');
    }

    const kem: HpkeKem = HpkePrimitiveFactory.createKemFromParams(params);
    const kdf: HpkeKdf = HpkePrimitiveFactory.createKdfFromParams(params);
    const aead: HpkeAead = HpkePrimitiveFactory.createAeadFromParams(params);
    const encapsulatedKeyLength =
        HpkeDecrypt.encodingSizeInBytes(params.getKem());
    const recipientKemPrivateKey : HpkeKemPrivateKey =
        await HpkeKemKeyFactory.createPrivate(recipientPrivateKey);
    return new HpkeDecrypt(
        recipientKemPrivateKey, kem, kdf, aead, encapsulatedKeyLength);
  }

  async decrypt(ciphertext: Uint8Array, contextInfo?: Uint8Array) {
    if (ciphertext.length <= this.encapsulatedKeyLength) {
      throw new SecurityException('Ciphertext is too short.');
    }

    if (!contextInfo) {
      contextInfo = new Uint8Array(0);
    }

    const encapsulatedKey = ciphertext.slice(0, this.encapsulatedKeyLength);
    const aeadCiphertext =
        ciphertext.slice(this.encapsulatedKeyLength, ciphertext.length);
    const context = await hpkeContext.createRecipientContext(
        encapsulatedKey, this.recipientPrivateKey, this.kem, this.kdf,
        this.aead, contextInfo);
    return context.open(aeadCiphertext, HpkeDecrypt.EMPTY_ASSOCIATED_DATA);
  }
}
