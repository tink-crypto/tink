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

/**
 * @fileoverview An implementation of HKDF, RFC 5869.
 */
import {InvalidArgumentsException} from '../exception/invalid_arguments_exception';

import {fromRawKey as hmacFromRawKey} from './hmac';
import * as Validators from './validators';

/**
 * Computes an HKDF.
 *
 * @param size The length of the generated pseudorandom string in
 *     bytes. The maximal size is 255 * DigestSize, where DigestSize is the size
 *     of the underlying HMAC.
 * @param hash the name of the hash function. Accepted names are SHA-1,
 *     SHA-256 and SHA-512
 * @param ikm Input keying material.
 * @param info Context and application specific
 *     information (can be a zero-length array).
 * @param opt_salt Salt value (a non-secret random
 *     value). If not provided, it is set to a string of hash length zeros.
 * @return Output keying material (okm).
 */
export async function compute(
    size: number, hash: string, ikm: Uint8Array, info: Uint8Array,
    opt_salt?: Uint8Array): Promise<Uint8Array> {
  let digestSize;
  if (!Number.isInteger(size)) {
    throw new InvalidArgumentsException('size must be an integer');
  }
  if (size <= 0) {
    throw new InvalidArgumentsException('size must be positive');
  }
  switch (hash) {
    case 'SHA-1':
      digestSize = 20;
      if (size > 255 * 20) {
        throw new InvalidArgumentsException('size too large');
      }
      break;
    case 'SHA-256':
      digestSize = 32;
      if (size > 255 * 32) {
        throw new InvalidArgumentsException('size too large');
      }
      break;
    case 'SHA-512':
      digestSize = 64;
      if (size > 255 * 64) {
        throw new InvalidArgumentsException('size too large');
      }
      break;
    default:
      throw new InvalidArgumentsException(hash + ' is not supported');
  }
  Validators.requireUint8Array(ikm);
  Validators.requireUint8Array(info);
  let salt = opt_salt;
  if (opt_salt == null || salt === undefined || salt.length == 0) {
    salt = new Uint8Array(digestSize);
  }
  Validators.requireUint8Array(salt);

  // Extract.
  let hmac = await hmacFromRawKey(hash, salt, digestSize);
  const prk = await hmac.computeMac(
      // Pseudorandom Key
      ikm);

  // Expand
  hmac = await hmacFromRawKey(hash, prk, digestSize);
  let ctr = 1;
  let pos = 0;
  let digest = new Uint8Array(0);
  const result = new Uint8Array(size);
  while (true) {
    const input = new Uint8Array(digest.length + info.length + 1);
    input.set(digest, 0);
    input.set(info, digest.length);
    input[input.length - 1] = ctr;
    digest = await hmac.computeMac(input);
    if (pos + digest.length < size) {
      result.set(digest, pos);
      pos += digest.length;
      ctr++;
    } else {
      result.set(digest.subarray(0, size - pos), pos);
      break;
    }
  }
  return result;
}
