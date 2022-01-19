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

import com.google.crypto.tink.KeyTemplate;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.GeneralSecurityException;

/**
 * Generates and adds a new key to a keyset.
 */
public class AddKeyCommand extends AddRotateOptions implements Command {
  @Override
  public void run() throws Exception {
    validate();
    add(outputStream, outFormat, inputStream, inFormat, masterKeyUri, credentialPath,
        keyTemplate);
  }

  /**
   * Generates and adds a new key to a keyset.
   *
   * <p>The keyset is read from {@code inputStream}. Its format can be either <code>json</code>
   * or <code>binary</code>, and is specified by {@code inFormat}. The new key is generated
   * from template {@code keyTemplate}. If the input keyset is encrypted, use
   * {@code masterKeyUri} and {@code credentialPath} to decrypt. The output keyset
   * is written to {@code outputStream} in {@code outFormat}, and encrypted if the
   * input keyset is encrypted.
   *
   * @throws GeneralSecurityException if cannot encrypt/decrypt the keyset
   * @throws IOException if cannot read/write the keyset
   */
  public static void add(OutputStream outputStream, String outFormat,
      InputStream inputStream, String inFormat,
      String masterKeyUri, String credentialPath,
      KeyTemplate keyTemplate) throws GeneralSecurityException, IOException {
    TinkeyUtil.createKey(TinkeyUtil.CommandType.ADD_KEY, outputStream, outFormat,
        inputStream, inFormat, masterKeyUri, credentialPath, keyTemplate);
  }
}
