/**
 * @license
 * Copyright 2020 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */

import {Aead} from '../aead/internal/aead';
import {SecurityException} from '../exception/security_exception';
import {HybridDecrypt} from '../hybrid/internal/hybrid_decrypt';

import {EciesAeadHkdfDemHelper} from './ecies_aead_hkdf_dem_helper';
import {EciesHkdfKemRecipient, fromJsonWebKey as kemRecipientFromJsonWebKey} from './ecies_hkdf_kem_recipient';
import * as EllipticCurves from './elliptic_curves';

/**
 * Implementation of ECIES AEAD HKDF hybrid decryption.
 *
 * @final
 */
export class EciesAeadHkdfHybridDecrypt extends HybridDecrypt {
  private readonly kemRecipient_: EciesHkdfKemRecipient;
  private readonly hkdfHash_: string;
  private readonly pointFormat_: EllipticCurves.PointFormatType;
  private readonly demHelper_: EciesAeadHkdfDemHelper;
  private readonly headerSize: number;
  private readonly hkdfSalt: Uint8Array|undefined;

  /**
   * @param hkdfHash the name of the HMAC algorithm, accepted names
   *     are: SHA-1, SHA-256 and SHA-512.
   */
  constructor(
      recipientPrivateKey: JsonWebKey, kemRecipient: EciesHkdfKemRecipient,
      hkdfHash: string, pointFormat: EllipticCurves.PointFormatType,
      demHelper: EciesAeadHkdfDemHelper, opt_hkdfSalt?: Uint8Array) {
    super();
    if (!recipientPrivateKey) {
      throw new SecurityException('Recipient private key has to be non-null.');
    }
    if (!kemRecipient) {
      throw new SecurityException('KEM recipient has to be non-null.');
    }
    if (!hkdfHash) {
      throw new SecurityException('HKDF hash algorithm has to be non-null.');
    }
    if (!pointFormat) {
      throw new SecurityException('Point format has to be non-null.');
    }
    if (!demHelper) {
      throw new SecurityException('DEM helper has to be non-null.');
    }
    const {crv} = recipientPrivateKey;
    if (!crv) {
      throw new SecurityException('Curve has to be defined.');
    }
    const curveType = EllipticCurves.curveFromString(crv);
    const headerSize =
        EllipticCurves.encodingSizeInBytes(curveType, pointFormat);
    this.kemRecipient_ = kemRecipient;
    this.hkdfHash_ = hkdfHash;
    this.pointFormat_ = pointFormat;
    this.demHelper_ = demHelper;
    this.headerSize = headerSize;
    this.hkdfSalt = opt_hkdfSalt;
  }

  /**
   * Decrypts ciphertext using opt_contextInfo as info parameter of the
   * underlying HKDF.
   *
   */
  async decrypt(ciphertext: Uint8Array, associatedData?: Uint8Array) {
    if (ciphertext.length < this.headerSize) {
      throw new SecurityException('Ciphertext is too short.');
    }

    // Split the ciphertext to KEM token and AEAD ciphertext.
    const kemToken = ciphertext.slice(0, this.headerSize);
    const ciphertextBody = ciphertext.slice(this.headerSize, ciphertext.length);
    const aead = await this.getAead(kemToken, associatedData);
    return aead.decrypt(ciphertextBody);
  }

  private async getAead(
      kemToken: Uint8Array, opt_contextInfo?: Uint8Array|null): Promise<Aead> {
    // Variable hkdfInfo is not optional for decapsulate method. Thus it should
    // be an empty array in case that it is not defined by the caller of decrypt
    // method.
    if (!opt_contextInfo) {
      opt_contextInfo = new Uint8Array(0);
    }
    const symmetricKey = await this.kemRecipient_.decapsulate(
        kemToken, this.demHelper_.getDemKeySizeInBytes(), this.pointFormat_,
        this.hkdfHash_, opt_contextInfo, this.hkdfSalt);
    return this.demHelper_.getAead(symmetricKey);
  }
}

/**
 * @param hkdfHash the name of the HMAC algorithm, accepted names
 *     are: SHA-1, SHA-256 and SHA-512.
 */
export async function fromJsonWebKey(
    recipientPrivateKey: JsonWebKey, hkdfHash: string,
    pointFormat: EllipticCurves.PointFormatType,
    demHelper: EciesAeadHkdfDemHelper,
    opt_hkdfSalt?: Uint8Array): Promise<HybridDecrypt> {
  if (!recipientPrivateKey) {
    throw new SecurityException('Recipient private key has to be non-null.');
  }
  if (!hkdfHash) {
    throw new SecurityException('HKDF hash algorithm has to be non-null.');
  }
  if (!pointFormat) {
    throw new SecurityException('Point format has to be non-null.');
  }
  if (!demHelper) {
    throw new SecurityException('DEM helper has to be non-null.');
  }
  if (!recipientPrivateKey) {
    throw new SecurityException('Recipient private key has to be non-null.');
  }
  const kemRecipient = await kemRecipientFromJsonWebKey(recipientPrivateKey);
  return new EciesAeadHkdfHybridDecrypt(
      recipientPrivateKey, kemRecipient, hkdfHash, pointFormat, demHelper,
      opt_hkdfSalt);
}
