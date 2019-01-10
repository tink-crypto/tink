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

package com.google.crypto.tink.testing;

import com.google.crypto.tink.BinaryKeysetReader;
import com.google.crypto.tink.CleartextKeysetHandle;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.config.TinkConfig;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.Charset;
import java.nio.file.Paths;
import java.security.GeneralSecurityException;

/**
 * Helper function for CLI applications.
 */
public class CliUtil {
  public static final Charset UTF_8 = Charset.forName("UTF-8");

  /**
   * Reads a keyset from the specified file.
   * In case of errors throws an exception.
   */
  public static KeysetHandle readKeyset(String filename)
      throws GeneralSecurityException, IOException {
    System.out.println("Reading the keyset...");
    return CleartextKeysetHandle.read(BinaryKeysetReader.withFile(new File(filename)));
  }

  /**
   * Initializes Tink registry.
   * In case of errors throws an exception.
   */
  public static void initTink() throws GeneralSecurityException {
    TinkConfig.register();
  }

  /**
   * Reads the specified file and returns the contents as a byte array.
   * In case of errors throws an exception.
   */
  public static byte[] read(String filename) throws GeneralSecurityException, IOException {
    System.out.println("Reading file " + filename);
    InputStream inputStream = new FileInputStream(Paths.get(filename).toFile());
    return read(inputStream);
  }

  /**
   * Reads the specified InputStream and returns the contents as a byte array.
   * In case of errors throws an exception.
   */
  public static byte[] read(InputStream inputStream) throws GeneralSecurityException, IOException {
    ByteArrayOutputStream result = new ByteArrayOutputStream();
    byte[] buffer = new byte[512];
    int length;
    while ((length = inputStream.read(buffer)) != -1) {
      result.write(buffer, 0, length);
    }
    inputStream.close();
    return result.toByteArray();
  }

  /**
   * Writes the given 'output' to the specified file.
   * In case of errors throws an exception.
   */
  public static void write(byte[] output, String filename) throws IOException {
    System.out.println("Writing to file " + filename);
    OutputStream outputStream = new FileOutputStream(Paths.get(filename).toFile());
    outputStream.write(output);
    outputStream.close();
  }
}
