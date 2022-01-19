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
import java.io.OutputStream;
import java.security.GeneralSecurityException;

/**
 * Creates a new keyset.
 */
public class CreateKeysetCommand extends CreateKeysetOptions implements Command {
  @Override
  public void run() throws Exception {
    validate();
    create(outputStream, outFormat, masterKeyUri, credentialPath, keyTemplate);
    outputStream.close();
  }

  /**
   * Create a new keyset.
   *
   * <p>Creates a keyset that contains a single key of template {@code keyTemplate}, and writes it
   * to {@code outputStream}. If {@code masterKeyUri} is not null, encrypt the output keyset with
   * {@code masterKeyUri} and {@code credentialPath}.
   *
   * @throws GeneralSecurityException if cannot generate or encrypt the output keyset
   * @throws IOException if cannot write the output keyset
   */
  public static void create(OutputStream outputStream, String outFormat,
      String masterKeyUri, String credentialPath, KeyTemplate keyTemplate)
      throws GeneralSecurityException, IOException {
    TinkeyUtil.createKeyset(outputStream, outFormat, masterKeyUri, credentialPath,
        keyTemplate);
  }
}
