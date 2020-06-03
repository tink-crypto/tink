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
import {InvalidArgumentsException} from '../exception/invalid_arguments_exception';
import {SecurityException} from '../exception/security_exception';
const SUPPORTED_AES_KEY_SIZES: number[] = [16, 32];

/**
 * Validates AES key sizes, at the moment only 128-bit and 256-bit keys are
 * supported.
 *
 * @param n the key size in bytes
 * @throws {!InvalidArgumentsException}
 * @static
 */
export function validateAesKeySize(n: number) {
  if (!SUPPORTED_AES_KEY_SIZES.includes(n)) {
    throw new InvalidArgumentsException('unsupported AES key size: ' + n);
  }
}

/**
 * Validates that the input is a non null Uint8Array.
 *
 * @throws {!InvalidArgumentsException}
 * @static
 */
export function requireUint8Array(input: Uint8Array) {
  if (input == null || !(input instanceof Uint8Array)) {
    throw new InvalidArgumentsException('input must be a non null Uint8Array');
  }
}

/**
 * Validates version, throws exception if candidate version is negative or
 * bigger than expected.
 *
 * @param candidate - version to be validated
 * @param maxVersion - upper bound on version
 * @throws {!SecurityException}
 * @static
 */
export function validateVersion(candidate: number, maxVersion: number) {
  if (candidate < 0 || candidate > maxVersion) {
    throw new SecurityException(
        'Version is out of bound, must be ' +
        'between 0 and ' + maxVersion + '.');
  }
}

/**
 * Validates ECDSA parameters.
 *
 * @throws {!SecurityException}
 */
export function validateEcdsaParams(curve: string, hash: string) {
  switch (curve) {
    case 'P-256':
      if (hash != 'SHA-256') {
        throw new SecurityException(
            'expected SHA-256 (because curve is P-256) but got ' + hash);
      }
      break;
    case 'P-384':
      if (hash != 'SHA-384' && hash != 'SHA-512') {
        throw new SecurityException(
            'expected SHA-384 or SHA-512 (because curve is P-384) but got ' +
            hash);
      }
      break;
    case 'P-521':
      if (hash != 'SHA-512') {
        throw new SecurityException(
            'expected SHA-512 (because curve is P-521) but got ' + hash);
      }
      break;
    default:
      throw new SecurityException('unsupported curve: ' + curve);
  }
}
