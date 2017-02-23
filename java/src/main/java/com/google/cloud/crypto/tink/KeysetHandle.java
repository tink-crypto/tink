// Copyright 2017 Google Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
////////////////////////////////////////////////////////////////////////////////

package com.google.cloud.crypto.tink;

import com.google.cloud.crypto.tink.TinkProto.Keyset;

/**
 * KeysetHandle provides abstracted access to Keysets, to limit the exposure
 * of actual protocol buffers that hold sensitive key material.
 *
 * NOTE: this is an initial definition of this interface, which needs more work.
 *   It should probably be an abstract class which does not provide public access
 *   to the actual key material.
 */
public interface KeysetHandle {
  /**
   * @returns source of the key material of this keyset (e.g. Keystore, Cloud KMS).
   */
  byte[] getSource();

  /**
   * @returns the actual keyset data.
   */
  Keyset getKeyset();
}
