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

import java.io.File;
import java.io.InputStream;
import java.io.OutputStream;

/**
 * Changes the master key of a keyset. The keyset will be encrypted with the new master key.
 */
public class ChangeMasterKeyCommand extends ChangeMasterKeyOptions implements Command {
  @Override
  public void run() throws Exception {
    validate();
    changeMasterKey(outputStream, inputStream, credentialFile, newMasterKeyValue,
        newCredentialFile);
  }

  /**
   * Reencrypts the keyset in {@code inputStream} using {@code newMasterKeyValue}, writes the
   * resulting keyset to {@code outputStream}.
   */
  public static void changeMasterKey(OutputStream outputStream, InputStream inputStream,
      File credentialFile, String newMasterKeyValue, File newCredentialFile)
      throws Exception {
    throw new Exception("Not Implemented Yet");
  }
}
