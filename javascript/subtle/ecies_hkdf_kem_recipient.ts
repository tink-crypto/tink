/**
 * @license
 * Copyright 2020 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */

import {SecurityException} from '../exception/security_exception';

import * as Bytes from './bytes';
import * as EllipticCurves from './elliptic_curves';
import * as Hkdf from './hkdf';

/**
 * HKDF-based ECIES-KEM (key encapsulation mechanism) for ECIES recipient.
 */
export class EciesHkdfKemRecipient {
  private readonly privateKey_: CryptoKey;

  constructor(privateKey: CryptoKey) {
    if (!privateKey) {
      throw new SecurityException('Private key has to be non-null.');
    }

    // CryptoKey should have the properties type and algorithm.
    if (privateKey.type !== 'private' || !privateKey.algorithm) {
      throw new SecurityException('Expected crypto key of type: private.');
    }
    this.privateKey_ = privateKey;
  }

  /**
   * @param kemToken the public ephemeral point.
   * @param keySizeInBytes The length of the generated pseudorandom
   *     string in bytes. The maximal size is 255 * DigestSize, where DigestSize
   *     is the size of the underlying HMAC.
   * @param pointFormat The format of the
   *     public ephemeral point.
   * @param hkdfHash the name of the hash function. Accepted names are
   *     SHA-1, SHA-256 and SHA-512.
   * @param hkdfInfo Context and application specific
   *     information (can be a zero-length array).
   * @param opt_hkdfSalt Salt value (a non-secret random
   *     value). If not provided, it is set to a string of hash length zeros.
   * @return The KEM key and token.
   */
  async decapsulate(
      kemToken: Uint8Array, keySizeInBytes: number,
      pointFormat: EllipticCurves.PointFormatType, hkdfHash: string,
      hkdfInfo: Uint8Array, opt_hkdfSalt?: Uint8Array): Promise<Uint8Array> {
    const {namedCurve}: Partial<EcKeyAlgorithm> = this.privateKey_.algorithm;
    if (!namedCurve) {
      throw new SecurityException('Curve has to be defined.');
    }
    const jwk = EllipticCurves.pointDecode(namedCurve, pointFormat, kemToken);
    const publicKey = await EllipticCurves.importPublicKey('ECDH', jwk);
    const sharedSecret = await EllipticCurves.computeEcdhSharedSecret(
        this.privateKey_, publicKey);
    const hkdfIkm = Bytes.concat(kemToken, sharedSecret);
    const kemKey = await Hkdf.compute(
        keySizeInBytes, hkdfHash, hkdfIkm, hkdfInfo, opt_hkdfSalt);
    return kemKey;
  }
}

export async function fromJsonWebKey(jwk: JsonWebKey):
    Promise<EciesHkdfKemRecipient> {
  const privateKey = await EllipticCurves.importPrivateKey('ECDH', jwk);
  return new EciesHkdfKemRecipient(privateKey);
}
