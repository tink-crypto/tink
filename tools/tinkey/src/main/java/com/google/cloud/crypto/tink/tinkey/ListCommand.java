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
 * List keys in a keyset.
 */
public class ListCommand extends InOptions implements Command {
  @Override
  public void run() throws Exception {
    validate();
    list(outputStream, outFormat, inputStream, inFormat, credentialFile);
  }

  /**
   * Lists all keys in the keyset in {@code inputStream} (using {@code credentialFile} to
   * decrypt if it is encrypted). This command doesn't output actual key material.
   */
  public static void list(OutputStream outputStream, String outFormat, InputStream inputStream,
      String inFormat, File credentialFile) throws Exception {
    throw new Exception("Not Implemented Yet");
  }
}
