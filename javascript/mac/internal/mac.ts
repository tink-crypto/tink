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
 * Interface for Message Authentication Codes (MAC).
 *
 * Security guarantees: Message Authentication Codes provide symmetric message
 * authentication. Instances implementing this interface are secure against
 * existential forgery under chosen plaintext attack, and can be deterministic
 * or randomized. This interface should be used for authentication only, and not
 * for other purposes like generation of pseudorandom bytes.
 *
 */
export abstract class Mac {
  /**
   * Computes message authentication code (MAC) for `data`.
   *
   * @param data the data to compute MAC
   * @return the MAC tag
   */
  abstract computeMac(data: Uint8Array): Promise<Uint8Array>;

  /**
   * Verifies whether `tag` is a correct authentication code for `data`.
   *
   * @param tag  the MAC tag
   * @param data the data to compute MAC
   */
  abstract verifyMac(tag: Uint8Array, data: Uint8Array): Promise<boolean>;
}
