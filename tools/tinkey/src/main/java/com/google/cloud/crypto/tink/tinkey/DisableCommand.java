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

package com.google.cloud.crypto.tink.tinkey;

/**
 * Disables a key with some key id in a keyset.
 */
public class DisableCommand extends KeyIdOptions implements Command {
  @Override
  public void run() throws Exception {
    disable(inFilename, credentialFilename, keyIdValue);
  }

  /**
   * Disables the key with {@code keyIdValue} in the keyset in {@code inFilename} (using
   * {@code credentialFilename} to decrypt if it is encrypted).
   * @throws GeneralSecurityException if the key is the primary key, or not found.
   */
  public static void disable(String inFilename, String credentialFilename, int keyIdValue)
      throws Exception {
    throw new Exception("Not Implemented Yet");
  }
}
