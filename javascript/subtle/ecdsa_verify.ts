// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//      http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
////////////////////////////////////////////////////////////////////////////////
import {SecurityException} from '../exception/security_exception';
import {PublicKeyVerify} from '../signature/internal/public_key_verify';

import * as EllipticCurves from './elliptic_curves';
import * as Validators from './validators';

/**
 * Implementation of ECDSA verifying.
 *
 * @final
 */
export class EcdsaVerify implements PublicKeyVerify {
  private readonly ieeeSignatureLength_: number;

  /**
   * @param encoding The
   *     encoding of the signature.
   */
  constructor(
      private readonly key: CryptoKey, private readonly hash: string,
      private readonly encoding: EllipticCurves.EcdsaSignatureEncodingType) {
    const {namedCurve}: Partial<EcKeyAlgorithm> = key.algorithm;
    if (!namedCurve) {
      throw new SecurityException('Curve has to be defined.');
    }
    this.ieeeSignatureLength_ = 2 *
        EllipticCurves.fieldSizeInBytes(
            EllipticCurves.curveFromString(namedCurve));
  }

  /**
   * @override
   */
  async verify(signature: Uint8Array, message: Uint8Array): Promise<boolean> {
    Validators.requireUint8Array(signature);
    Validators.requireUint8Array(message);
    if (this.encoding === EllipticCurves.EcdsaSignatureEncodingType.DER) {
      signature =
          EllipticCurves.ecdsaDer2Ieee(signature, this.ieeeSignatureLength_);
    }
    return window.crypto.subtle.verify(
        {name: 'ECDSA', hash: {name: this.hash}}, this.key, signature, message);
  }
}

/**
 * @param opt_encoding The
 *     optional encoding of the signature. If absent, default is IEEE P1363.
 */
export async function fromJsonWebKey(
    jwk: JsonWebKey, hash: string,
    encoding: EllipticCurves.EcdsaSignatureEncodingType =
        EllipticCurves.EcdsaSignatureEncodingType.IEEE_P1363):
    Promise<PublicKeyVerify> {
  if (!jwk) {
    throw new SecurityException('public key has to be non-null');
  }
  const {crv} = jwk;
  if (!crv) {
    throw new SecurityException('curve has to be defined');
  }
  Validators.validateEcdsaParams(crv, hash);
  const cryptoKey = await EllipticCurves.importPublicKey('ECDSA', jwk);
  return new EcdsaVerify(cryptoKey, hash, encoding);
}
