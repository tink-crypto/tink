/**
 * @license
 * Copyright 2020 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */

import {SecurityException} from '../exception/security_exception';
import {HybridEncrypt} from '../hybrid/internal/hybrid_encrypt';

import * as Bytes from './bytes';
import {EciesAeadHkdfDemHelper} from './ecies_aead_hkdf_dem_helper';
import * as sender from './ecies_hkdf_kem_sender';
import * as EllipticCurves from './elliptic_curves';

/**
 * Implementation of ECIES AEAD HKDF hybrid encryption.
 *
 * @final
 */
export class EciesAeadHkdfHybridEncrypt extends HybridEncrypt {
  private readonly kemSender_: sender.EciesHkdfKemSender;
  private readonly hkdfHash_: string;
  private readonly pointFormat_: EllipticCurves.PointFormatType;
  private readonly demHelper_: EciesAeadHkdfDemHelper;
  private readonly hkdfSalt: Uint8Array|undefined;

  /**
   * @param hkdfHash the name of the HMAC algorithm, accepted names
   *     are: SHA-1, SHA-256 and SHA-512.
   */
  constructor(
      kemSender: sender.EciesHkdfKemSender, hkdfHash: string,
      pointFormat: EllipticCurves.PointFormatType,
      demHelper: EciesAeadHkdfDemHelper, opt_hkdfSalt?: Uint8Array) {
    super();
    // TODO(thaidn): do we actually need these null checks?
    if (!kemSender) {
      throw new SecurityException('KEM sender has to be non-null.');
    }
    if (!hkdfHash) {
      throw new SecurityException('HMAC algorithm has to be non-null.');
    }
    if (!pointFormat) {
      throw new SecurityException('Point format has to be non-null.');
    }
    if (!demHelper) {
      throw new SecurityException('DEM helper has to be non-null.');
    }
    this.kemSender_ = kemSender;
    this.hkdfHash_ = hkdfHash;
    this.pointFormat_ = pointFormat;
    this.demHelper_ = demHelper;
    this.hkdfSalt = opt_hkdfSalt;
  }

  /**
   * Encrypts plaintext using opt_contextInfo as info parameter of the
   * underlying HKDF.
   *
   */
  async encrypt(
      plaintext: Uint8Array,
      associatedData: Uint8Array = new Uint8Array(0)): Promise<Uint8Array> {
    const keySizeInBytes = this.demHelper_.getDemKeySizeInBytes();
    const kemKey = await this.kemSender_.encapsulate(
        keySizeInBytes, this.pointFormat_, this.hkdfHash_, associatedData,
        this.hkdfSalt);
    const aead = await this.demHelper_.getAead(kemKey['key']);
    const ciphertextBody = await aead.encrypt(plaintext);
    const header = kemKey['token'];
    return Bytes.concat(header, ciphertextBody);
  }
}

/**
 * @param hkdfHash the name of the HMAC algorithm, accepted names
 *     are: SHA-1, SHA-256 and SHA-512.
 */
export async function fromJsonWebKey(
    recipientPublicKey: JsonWebKey, hkdfHash: string,
    pointFormat: EllipticCurves.PointFormatType,
    demHelper: EciesAeadHkdfDemHelper,
    opt_hkdfSalt?: Uint8Array): Promise<HybridEncrypt> {
  if (!recipientPublicKey) {
    throw new SecurityException('Recipient public key has to be non-null.');
  }
  if (!hkdfHash) {
    throw new SecurityException('HMAC algorithm has to be non-null.');
  }
  if (!pointFormat) {
    throw new SecurityException('Point format has to be non-null.');
  }
  if (!demHelper) {
    throw new SecurityException('DEM helper has to be non-null.');
  }
  const kemSender = await sender.fromJsonWebKey(recipientPublicKey);
  return new EciesAeadHkdfHybridEncrypt(
      kemSender, hkdfHash, pointFormat, demHelper, opt_hkdfSalt);
}
