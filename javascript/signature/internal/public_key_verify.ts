// Copyright 2018 Google LLC.
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
 * Interface for verifying digital signatures.
 *
 * Security guarantees: Implementations of these interfaces are secure
 * against adaptive chosen-message attacks. Signing data ensures the
 * authenticity and the integrity of that data, but not its secrecy.
 *
 */
export abstract class PublicKeyVerify {
  /**
   * Verifies the `signature` of `message`.
   *
   * @param signature the signature, must be non-null.
   * @param message the message, must be non-null.
   * @return true iff the signature is valid, false
   *     otherwise.
   */
  abstract verify(signature: Uint8Array, message: Uint8Array): Promise<boolean>;
}
