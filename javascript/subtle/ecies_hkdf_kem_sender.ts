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
 * HKDF-based ECIES-KEM (key encapsulation mechanism) for ECIES sender.
 */
export class EciesHkdfKemSender {
  private readonly publicKey: CryptoKey;

  constructor(recipientPublicKey: CryptoKey) {
    if (!recipientPublicKey) {
      throw new SecurityException('Recipient public key has to be non-null.');
    }

    // CryptoKey should have the properties type and algorithm.
    if (recipientPublicKey.type !== 'public' || !recipientPublicKey.algorithm) {
      throw new SecurityException('Expected Crypto key of type: public.');
    }
    this.publicKey = recipientPublicKey;
  }

  /**
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
   * @return The KEM key and
   *     token.
   */
  async encapsulate(
      keySizeInBytes: number, pointFormat: EllipticCurves.PointFormatType,
      hkdfHash: string, hkdfInfo: Uint8Array, opt_hkdfSalt?: Uint8Array):
      Promise<{key: Uint8Array, token: Uint8Array}> {
    const {namedCurve}: Partial<EcKeyAlgorithm> = this.publicKey.algorithm;
    if (!namedCurve) {
      throw new SecurityException('Curve has to be defined.');
    }
    const ephemeralKeyPair =
        await EllipticCurves.generateKeyPair('ECDH', namedCurve);
    const sharedSecret = await EllipticCurves.computeEcdhSharedSecret(
        ephemeralKeyPair.privateKey!, this.publicKey);
    const jwk =
        await EllipticCurves.exportCryptoKey(ephemeralKeyPair.publicKey!);
    const {crv} = jwk;
    if (!crv) {
      throw new SecurityException('Curve has to be defined.');
    }
    const kemToken = EllipticCurves.pointEncode(crv, pointFormat, jwk);
    const hkdfIkm = Bytes.concat(kemToken, sharedSecret);
    const kemKey = await Hkdf.compute(
        keySizeInBytes, hkdfHash, hkdfIkm, hkdfInfo, opt_hkdfSalt);
    return {'key': kemKey, 'token': kemToken};
  }
}

export async function fromJsonWebKey(jwk: JsonWebKey):
    Promise<EciesHkdfKemSender> {
  const publicKey = await EllipticCurves.importPublicKey('ECDH', jwk);
  return new EciesHkdfKemSender(publicKey);
}
