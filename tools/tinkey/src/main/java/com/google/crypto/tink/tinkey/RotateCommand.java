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

import com.google.crypto.tink.proto.KeyTemplate;
import java.io.File;
import java.io.InputStream;
import java.io.OutputStream;

/**
 * Rotates an existing keyset.
 */
public class RotateCommand extends AddRotateOptions implements Command {
  @Override
  public void run() throws Exception {
    rotate(outputStream, outFormat, inputStream, inFormat, credentialFile, keyTemplate);
  }

  /**
   * Generates and adds a key of template {@code keyTemplate} to the keyset in
   * {@code inputStream} (using {@code credentialFile} to decrypt if it is encrypted).
   * The new key becomes the primary key.
   * Writes the resulting keyset to {@code outputStream}.
   */
  public static void rotate(OutputStream outputStream, String outFormat,
      InputStream inputStream, String inFormat,
      File credentialFile, KeyTemplate keyTemplate) throws Exception {
    throw new Exception("Not Implemented Yet");
  }
}
