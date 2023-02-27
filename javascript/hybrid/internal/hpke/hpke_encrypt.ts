/**
 * @license
 * Copyright 2023 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */

import {InvalidArgumentsException} from '../../../exception/invalid_arguments_exception';
import {PbHpkeParams, PbHpkePublicKey} from '../../../internal/proto';
import {bytesAsU8} from '../../../internal/proto_shims';
import * as bytes from '../../../subtle/bytes';
import {HybridEncrypt} from '../hybrid_encrypt';

import {HpkeAead} from './hpke_aead';
import * as hpkeContext from './hpke_context';
import {HpkeKdf} from './hpke_kdf';
import {HpkeKem} from './hpke_kem';
import {HpkePrimitiveFactory} from './hpke_primitive_factory';

/**
 * Hybrid Public Key Encryption (HPKE) encryption.
 *
 * @final
 */
export class HpkeEncrypt extends HybridEncrypt {
  private static readonly EMPTY_ASSOCIATED_DATA = new Uint8Array(0);

  private readonly recipientPublicKey: PbHpkePublicKey;
  private readonly kem: HpkeKem;
  private readonly kdf: HpkeKdf;
  private readonly aead: HpkeAead;

  constructor(
      recipientPublicKey: PbHpkePublicKey, kem: HpkeKem, kdf: HpkeKdf,
      aead: HpkeAead) {
    super();
    if (!recipientPublicKey) {
      throw new InvalidArgumentsException(
          'Recipient public key must be non-null.');
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

    this.recipientPublicKey = recipientPublicKey;
    this.kem = kem;
    this.kdf = kdf;
    this.aead = aead;
  }

  /**
   * Returns an HPKE encryption primitive created from a given
   * recipient public key.
   */
  static async createHpkeEncrypt(recipientPublicKey: PbHpkePublicKey) {
    if (bytesAsU8(recipientPublicKey.getPublicKey()).length === 0) {
      throw new InvalidArgumentsException('Recipient public key is empty.');
    }
    const params: PbHpkeParams|undefined = recipientPublicKey.getParams();
    if (!params) {
      throw new InvalidArgumentsException(
          'Public key is missing params field.');
    }

    const kem: HpkeKem = HpkePrimitiveFactory.createKemFromParams(params);
    const kdf: HpkeKdf = HpkePrimitiveFactory.createKdfFromParams(params);
    const aead: HpkeAead = HpkePrimitiveFactory.createAeadFromParams(params);
    return new HpkeEncrypt(recipientPublicKey, kem, kdf, aead);
  }

  async encrypt(plaintext: Uint8Array, contextInfo?: Uint8Array) {
    if (!contextInfo) {
      contextInfo = new Uint8Array(0);
    }

    const recipientPublicKeyBytes =
        bytesAsU8(this.recipientPublicKey.getPublicKey());
    const context = await hpkeContext.createSenderContext(
        recipientPublicKeyBytes, this.kem, this.kdf, this.aead, contextInfo);
    const ciphertext =
        await context.seal(plaintext, HpkeEncrypt.EMPTY_ASSOCIATED_DATA);
    return bytes.concat(context.getEncapsulatedKey(), ciphertext);
  }
}
