/**
 * @license
 * Copyright 2020 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */

import {SecurityException} from '../exception/security_exception';
import {PublicKeySign} from '../signature/internal/public_key_sign';

import * as EllipticCurves from './elliptic_curves';
import * as Validators from './validators';

/**
 * Implementation of ECDSA signing.
 *
 * @final
 */
export class EcdsaSign implements PublicKeySign {
  private readonly encoding_: EllipticCurves.EcdsaSignatureEncodingType;

  /**
   * @param opt_encoding The
   *     optional encoding of the signature. If absent, default is IEEE P1363.
   */
  constructor(
      private readonly key: CryptoKey, private readonly hash: string,
      opt_encoding?: EllipticCurves.EcdsaSignatureEncodingType|null) {
    if (!opt_encoding) {
      opt_encoding = EllipticCurves.EcdsaSignatureEncodingType.IEEE_P1363;
    }
    this.encoding_ = opt_encoding;
  }

  /**
   * @override
   */
  async sign(message: Uint8Array): Promise<Uint8Array> {
    Validators.requireUint8Array(message);
    const signature = await window.crypto.subtle.sign(
        {name: 'ECDSA', hash: {name: this.hash}}, this.key, message);
    if (this.encoding_ == EllipticCurves.EcdsaSignatureEncodingType.DER) {
      return EllipticCurves.ecdsaIeee2Der(new Uint8Array(signature));
    }
    return new Uint8Array(signature);
  }
}

/**
 * @param opt_encoding The
 *     optional encoding of the signature. If absent, default is IEEE P1363.
 */
export async function fromJsonWebKey(
    jwk: JsonWebKey, hash: string,
    opt_encoding?: EllipticCurves.EcdsaSignatureEncodingType|
    null): Promise<PublicKeySign> {
  if (!jwk) {
    throw new SecurityException('private key has to be non-null');
  }
  const {crv} = jwk;
  if (!crv) {
    throw new SecurityException('curve has to be defined');
  }
  Validators.validateEcdsaParams(crv, hash);
  const cryptoKey = await EllipticCurves.importPrivateKey('ECDSA', jwk);
  return new EcdsaSign(cryptoKey, hash, opt_encoding);
}
