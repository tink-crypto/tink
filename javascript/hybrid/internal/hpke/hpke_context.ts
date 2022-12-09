/**
 * @license
 * Copyright 2022 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */

import {SecurityException} from '../../../exception/security_exception';
import * as bytes from '../../../subtle/bytes';

import {HpkeAead} from './hpke_aead';
import {HpkeKdf} from './hpke_kdf';
import {HpkeKem} from './hpke_kem';
import {HpkeKemEncapOutput} from './hpke_kem_encap_output';
import * as hpkeUtil from './hpke_util';
import {NistCurvesHpkeKemPrivateKey} from './nist_curves_hpke_kem_private_key';

/**
 * Hybrid Public Key Encryption (HPKE) context for either a sender or a
 * recipient.
 *
 * @see https://www.rfc-editor.org/rfc/rfc9180.html#name-creating-the-encryption-con
 */
export class HpkeContext {
  private sequenceNumber: bigint;
  private readonly maxSequenceNumber: bigint;

  constructor(
      private readonly encapsulatedKey: Uint8Array,
      private readonly key: Uint8Array, private readonly baseNonce: Uint8Array,
      private readonly aead: HpkeAead) {
    this.sequenceNumber = BigInt(0);

    /**
     * Indicates that the message limit is reached, calculated as per
     * @see https://www.rfc-editor.org/rfc/rfc9180.html#section-5.2-11.
     */
    this.maxSequenceNumber =
        (BigInt(1) << BigInt(8 * this.aead.getNonceLength())) - BigInt(1);
  }

  /**
   * Performs AEAD encryption of `plaintext` with `associatedData`
   * according to `ContextS.Seal()` as defined in
   * @see https://www.rfc-editor.org/rfc/rfc9180.html#section-5.2-8.
   */
  async seal(plaintext: Uint8Array, associatedData: Uint8Array):
      Promise<Uint8Array> {
    const nonce: Uint8Array = this.computeNonceAndIncrementSequenceNumber();
    return await this.aead.seal(
        {key: this.key, nonce, plaintext, associatedData});
  }

  /**
   * Performs AEAD decryption of `ciphertext` with `associatedData`
   * according to `ContextR.Open()` as defined in
   * @see https://www.rfc-editor.org/rfc/rfc9180.html#section-5.2-10.
   */
  async open(ciphertext: Uint8Array, associatedData: Uint8Array):
      Promise<Uint8Array> {
    const nonce: Uint8Array = this.computeNonceAndIncrementSequenceNumber();
    return this.aead.open({key: this.key, nonce, ciphertext, associatedData});
  }

  /**
   * Computes nonce according to `ComputeNonce` as defined in
   * @see https://www.rfc-editor.org/rfc/rfc9180.html#section-5.2-11.
   * for seal/open and increments the sequence number.
   */
  private computeNonceAndIncrementSequenceNumber(): Uint8Array {
    const seqBytes: Uint8Array = hpkeUtil.bigIntToByteArray(
        this.aead.getNonceLength(), this.sequenceNumber);
    const nonce: Uint8Array = bytes.xor(this.baseNonce, seqBytes);

    if (this.sequenceNumber >= this.maxSequenceNumber) {
      throw new SecurityException('message limit reached');
    }
    this.sequenceNumber += (BigInt(1));

    return nonce;
  }

  getKey(): Uint8Array {
    return this.key;
  }

  getBaseNonce(): Uint8Array {
    return this.baseNonce;
  }

  getEncapsulatedKey(): Uint8Array {
    return this.encapsulatedKey;
  }
}

/** Helper function factored out to facilitate unit testing. */
export async function createContext(
    encapsulatedKey: Uint8Array, sharedSecret: Uint8Array, kem: HpkeKem,
    kdf: HpkeKdf, aead: HpkeAead, info: Uint8Array): Promise<HpkeContext> {
  const suiteId = hpkeUtil.hpkeSuiteId(
      {kemId: kem.getKemId(), kdfId: kdf.getKdfId(), aeadId: aead.getAeadId()});

  /**
   * The IKM values below are empty because we only support base mode
   * @see https://www.rfc-editor.org/rfc/rfc9180.html#section-5.1.9.
   */
  const pskIdHash = await kdf.labeledExtract({
    ikm: new Uint8Array(0),  // empty IKM
    ikmLabel: 'psk_id_hash',
    suiteId,
  });

  const infoHash = await kdf.labeledExtract({
    ikm: info,
    ikmLabel: 'info_hash',
    suiteId,
  });

  const keyScheduleContext =
      bytes.concat(hpkeUtil.BASE_MODE, pskIdHash, infoHash);
  const secret = await kdf.labeledExtract({
    ikm: new Uint8Array(0),  // empty IKM
    ikmLabel: 'secret',
    suiteId,
    salt: sharedSecret
  });

  const key = await kdf.labeledExpand({
    prk: secret,
    info: keyScheduleContext,
    infoLabel: 'key',
    suiteId,
    length: aead.getKeyLength()
  });
  const baseNonce = await kdf.labeledExpand({
    prk: secret,
    info: keyScheduleContext,
    infoLabel: 'base_nonce',
    suiteId,
    length: aead.getNonceLength()
  });

  return new HpkeContext(encapsulatedKey, key, baseNonce, aead);
}

/**
 * Creates HPKE sender context according to `KeySchedule` as defined in
 * @see https://www.rfc-editor.org/rfc/rfc9180.html#section-5.1-9.
 */
export async function createSenderContext(
    recipientPublicKey: Uint8Array, kem: HpkeKem, kdf: HpkeKdf, aead: HpkeAead,
    info: Uint8Array): Promise<HpkeContext> {
  const encapOutput: HpkeKemEncapOutput =
      await kem.encapsulate(recipientPublicKey);
  const encapsulatedKey: Uint8Array = encapOutput.encapsulatedKey;
  const sharedSecret: Uint8Array = encapOutput.sharedSecret;
  return await createContext(
      encapsulatedKey, sharedSecret, kem, kdf, aead, info);
}

/**
 * Creates HPKE recipient context according to `KeySchedule` as defined in
 * @see https://www.rfc-editor.org/rfc/rfc9180.html#section-5.1-9.
 */
export async function createRecipientContext(
    encapsulatedKey: Uint8Array,
    recipientPrivateKey: NistCurvesHpkeKemPrivateKey, kem: HpkeKem,
    kdf: HpkeKdf, aead: HpkeAead, info: Uint8Array): Promise<HpkeContext> {
  const sharedSecret: Uint8Array =
      await kem.decapsulate(encapsulatedKey, recipientPrivateKey);
  return await createContext(
      encapsulatedKey, sharedSecret, kem, kdf, aead, info);
}
