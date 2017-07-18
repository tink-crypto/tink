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

import com.google.crypto.tink.KeysetHandle;
import java.io.File;
import java.io.InputStream;
import java.io.OutputStream;

/**
 * Creates a public keyset from an existing private keyset.
 */
public class CreatePublicKeysetCommand extends InOptions implements Command {
  @Override
  public void run() throws Exception {
    create(outputStream, outFormat, inputStream, inFormat, credentialFile);
  }

  /**
   * Extracts public keys from {@code inputStream} (using {@code credentialFile} to decrypt
   * if it is encrypted) and writes public keys to {@code outputStream}.
   */
  public static void create(OutputStream outputStream, String outFormat,
      InputStream inputStream, String inFormat, File credentialFile) throws Exception {
    KeysetHandle privateHandle = TinkeyUtil.getKeysetHandle(inputStream, inFormat, credentialFile);
    TinkeyUtil.writeProto(privateHandle.getPublicKeysetHandle().getKeyset(), outputStream,
        outFormat);
  }
}
