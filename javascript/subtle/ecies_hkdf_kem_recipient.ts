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
