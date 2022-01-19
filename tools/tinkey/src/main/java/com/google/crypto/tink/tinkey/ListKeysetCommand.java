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
import com.google.crypto.tink.proto.KeysetInfo;
import java.io.InputStream;

/**
 * List keys in a keyset.
 */
public class ListKeysetCommand extends InOptions implements Command {
  @Override
  public void run() throws Exception {
    validate();
    list(inputStream, inFormat, masterKeyUri, credentialPath);
  }

  /**
   * Lists all keys in the keyset in {@code inputStream} (using {@code credentialPath} to
   * decrypt if it is encrypted). This command doesn't output actual key material.
   */
  public static void list(InputStream inputStream,
      String inFormat, String masterKeyUri, String credentialPath) throws Exception {
    KeysetHandle handle = TinkeyUtil.getKeysetHandle(inputStream, inFormat, masterKeyUri,
        credentialPath);
    KeysetInfo keysetInfo = handle.getKeysetInfo();
    System.out.println(keysetInfo);
  }
}
