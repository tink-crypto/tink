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

import com.google.crypto.tink.Aead;
import com.google.crypto.tink.CleartextKeysetHandle;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.KeysetManager;
import com.google.crypto.tink.KmsClients;
import com.google.crypto.tink.proto.KeyTemplate;
import java.io.InputStream;
import java.io.OutputStream;

/**
 * Generates, adds a new key to an existing keyset and sets the new key as the primary
 * key.
 */
public class RotateCommand extends AddRotateOptions implements Command {
  @Override
  public void run() throws Exception {
    validate();
    rotate(outputStream, outFormat, inputStream, inFormat, masterKeyUri, credentialPath,
        keyTemplate);
  }

  /**
   * Generates and adds a key of template {@code keyTemplate} to the keyset in
   * {@code inputStream} (using {@code credentialPath} to decrypt if it is encrypted).
   * Sets the new key as the primary key and writes the resulting keyset to
   * {@code outputStream}.
   */
  public static void rotate(OutputStream outputStream, String outFormat,
      InputStream inputStream, String inFormat,
      String masterKeyUri, String credentialPath,
      KeyTemplate keyTemplate) throws Exception {
    KeysetHandle handle = TinkeyUtil.getKeysetHandle(inputStream, inFormat, masterKeyUri,
        credentialPath);
    if (masterKeyUri != null) {
      Aead masterKey = KmsClients.getAutoLoaded(masterKeyUri)
          .withCredentials(credentialPath)
          .getAead(masterKeyUri);
      KeysetManager.withKeysetHandle(handle)
          .rotate(keyTemplate)
          .getKeysetHandle()
          .write(TinkeyUtil.createKeysetWriter(outputStream, outFormat), masterKey);
    } else {
      CleartextKeysetHandle.write(
          KeysetManager.withKeysetHandle(handle)
              .rotate(keyTemplate)
              .getKeysetHandle(),
          TinkeyUtil.createKeysetWriter(outputStream, outFormat));
    }
  }
}
