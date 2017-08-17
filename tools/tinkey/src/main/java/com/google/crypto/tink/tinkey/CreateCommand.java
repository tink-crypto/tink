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

import com.google.crypto.tink.KeysetWriter;
import com.google.crypto.tink.proto.KeyTemplate;
import java.io.OutputStream;

/**
 * Creates a new keyset.
 */
public class CreateCommand extends CreateOptions implements Command {
  @Override
  public void run() throws Exception {
    validate();
    create(outputStream, outFormat, keyTemplate, masterKeyUri, credentialPath);
    outputStream.close();
  }

  /**
   * Creates a keyset that contains a single key of template {@code keyTemplate}, and writes it
   * to {@code outputStream}. Attempts to encrypt the keyset using {@code credentialPath} and
   * {@code masterKeyUri}.
   */
  public static void create(OutputStream outputStream, String outFormat,
      KeyTemplate keyTemplate, String masterKeyUri, String credentialPath)
      throws Exception {
    KeysetWriter writer = TinkeyUtil.createKeysetWriter(outputStream, outFormat);
    TinkeyUtil.generateKeyset(keyTemplate, writer, masterKeyUri, credentialPath);
  }
}
