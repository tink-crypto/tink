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

package com.google.crypto.tink.tinkey;

import java.io.InputStream;
import java.io.OutputStream;

/**
 * Promotes a specified key to primary.
 */
public class PromoteKeyCommand extends KeyIdOptions implements Command {
  @Override
  public void run() throws Exception {
    validate();
    promote(outputStream, outFormat, inputStream, inFormat,
        masterKeyUri, credentialPath, keyId);
  }

  /**
   * Promotes the key with {@code keyId} to become the primary (using {@code masterKeyUri}
   * {@code credentialPath} to decrypt if it is encrypted).
   * @throws GeneralSecurityException if the key is not found or disabled.
   */
  public static void promote(OutputStream outputStream, String outFormat,
      InputStream inputStream, String inFormat, String masterKeyUri,
      String credentialPath, int keyId) throws Exception {
    TinkeyUtil.manipulateKey(TinkeyUtil.CommandType.PROMOTE_KEY, outputStream, outFormat,
      inputStream, inFormat, masterKeyUri, credentialPath, keyId);
  }
}
