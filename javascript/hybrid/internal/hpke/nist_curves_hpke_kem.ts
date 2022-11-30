/**
 * @license
 * Copyright 2022 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */

import * as bytes from '../../../subtle/bytes';
import * as ellipticCurves from '../../../subtle/elliptic_curves';

import {HkdfHpkeKdf} from './hkdf_hpke_kdf';
import {HpkeKem} from './hpke_kem';
import {HpkeKemEncapOutput} from './hpke_kem_encap_output';
import {HpkeKemPrivateKey} from './hpke_kem_private_key';
import * as hpkeUtil from './hpke_util';
import * as nistCurvesHpkeKemPrivateKey from './nist_curves_hpke_kem_private_key';

/** Diffie-Hellman-based P-256 and P-521 HPKE KEM variant. */
export class NistCurvesHpkeKem implements HpkeKem {
  private constructor(
      private readonly hkdf: HkdfHpkeKdf,
      private readonly curve: ellipticCurves.CurveType.P256|
      ellipticCurves.CurveType.P521) {}

  /* Exported encapsulateHelper (insecure) to be used for unit tests. */
  TEST_ONLY = this.encapsulateHelper;

  /** Construct HPKE KEM using `curve`. */
  static fromCurve(curve: ellipticCurves.CurveType.P256|
                   ellipticCurves.CurveType.P521): NistCurvesHpkeKem {
    switch (curve) {
      case ellipticCurves.CurveType.P256:
        return new NistCurvesHpkeKem(
            new HkdfHpkeKdf('SHA-256'), ellipticCurves.CurveType.P256);

      case ellipticCurves.CurveType.P521:
        return new NistCurvesHpkeKem(
            new HkdfHpkeKdf('SHA-512'), ellipticCurves.CurveType.P521);
    }
  }

  private async deriveKemSharedSecret(
      dhSharedSecret: Uint8Array, senderPublicKey: Uint8Array,
      recipientPublicKey: Uint8Array): Promise<Uint8Array> {
    const kemContext: Uint8Array =
        bytes.concat(senderPublicKey, recipientPublicKey);

    const kemSuiteID: Uint8Array = hpkeUtil.kemSuiteId(this.getKemId());

    return await this.hkdf.extractAndExpand({
      ikm: dhSharedSecret,
      ikmLabel: 'eae_prk',
      info: kemContext,
      infoLabel: 'shared_secret',
      suiteId: kemSuiteID,
      length: this.hkdf.getMacLength()
    });
  }

  /** Helper function factored out (insecure) to facilitate unit testing. */
  private async encapsulateHelper(
      recipientPublicKey: Uint8Array,
      senderKeyPair: HpkeKemPrivateKey): Promise<HpkeKemEncapOutput> {
    const recipientPublicCryptoKey: CryptoKey =
        await hpkeUtil.getPublicKeyFromByteArray(
            ellipticCurves.curveToString(this.curve), recipientPublicKey);

    const dhSharedSecret: Uint8Array =
        await ellipticCurves.computeEcdhSharedSecret(
            senderKeyPair.privateKey, recipientPublicCryptoKey);

    const senderPublicKey: Uint8Array =
        await senderKeyPair.getSerializedPublicKey();

    const kemSharedSecret: Uint8Array = await this.deriveKemSharedSecret(
        dhSharedSecret, senderPublicKey, recipientPublicKey);

    const output: HpkeKemEncapOutput = {
      sharedSecret: kemSharedSecret,
      encapsulatedKey: senderPublicKey,
    };
    return output;
  }

  async encapsulate(recipientPublicKey: Uint8Array):
      Promise<HpkeKemEncapOutput> {
    const keyPair: CryptoKeyPair = await ellipticCurves.generateKeyPair(
        'ECDH', ellipticCurves.curveToString(this.curve));

    return await this.encapsulateHelper(
        recipientPublicKey,
        await nistCurvesHpkeKemPrivateKey.fromCryptoKeyPair(keyPair));
  }

  async decapsulate(
      encapsulatedKey: Uint8Array,
      recipientPrivateKey: HpkeKemPrivateKey): Promise<Uint8Array> {
    const privateKey = recipientPrivateKey.privateKey;

    const publicKey: CryptoKey = await hpkeUtil.getPublicKeyFromByteArray(
        ellipticCurves.curveToString(this.curve), encapsulatedKey);

    const dhSharedSecret: Uint8Array =
        await ellipticCurves.computeEcdhSharedSecret(privateKey, publicKey);

    return this.deriveKemSharedSecret(
        dhSharedSecret, encapsulatedKey,
        await recipientPrivateKey.getSerializedPublicKey());
  }

  getKemId(): Uint8Array {
    switch (this.curve) {
      case ellipticCurves.CurveType.P256:
        return hpkeUtil.P256_HKDF_SHA256_KEM_ID;
      case ellipticCurves.CurveType.P521:
        return hpkeUtil.P521_HKDF_SHA512_KEM_ID;
    }
  }
}
