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

import com.google.crypto.tink.CleartextKeysetHandle;
import com.google.crypto.tink.HybridEncrypt;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.hybrid.HybridEncryptConfig;
import com.google.crypto.tink.hybrid.HybridEncryptFactory;
import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.Charset;
import java.nio.file.Paths;

/**
 * A command-line utility for testing HybridEncrypt-primitives.
 * It requires 4 arguments:
 *  keyset-file:  name of the file with the keyset to be used for encryption
 *  plaintext-file:  name of the file that contains plaintext to be encrypted
 *  context-info:  a string to be used as "context info" during the encryption
 *  output-file:  name of the output file for the resulting ciphertext
 */
public class HybridEncryptCli {
  private static byte[] getStreamContents(InputStream inputStream) throws IOException {
    ByteArrayOutputStream result = new ByteArrayOutputStream();
    byte[] buffer = new byte[1024];
    int length;
    while ((length = inputStream.read(buffer)) != -1) {
      result.write(buffer, 0, length);
    }
    return result.toByteArray();
  }

  public static void main(String[] args) throws Exception {
    if (args.length != 4) {
      System.out.println(
          "Usage: HybridEncryptCli keyset-file plaintext-file context-info output-file");
      System.exit(1);
    }
    String keysetFilename = args[0];
    String plaintextFilename = args[1];
    String contextInfo = args[2];
    String outputFilename = args[3];
    System.out.println("Using keyset from file " + keysetFilename + " to encrypt file "
        + plaintextFilename + " with context info '" + contextInfo + "'.");
    System.out.println("The resulting ciphertext will be written to file " + outputFilename);

    // Read the keyset.
    System.out.println("Reading the keyset...");
    InputStream keysetStream = new FileInputStream(Paths.get(keysetFilename).toFile());
    KeysetHandle keysetHandle = CleartextKeysetHandle.parseFrom(keysetStream);
    keysetStream.close();

    // Get the primitive.
    System.out.println("Getting the primitive...");
    HybridEncryptConfig.registerStandardKeyTypes();
    HybridEncrypt hybridEncrypt = HybridEncryptFactory.getPrimitive(keysetHandle);

    // Read the plaintext.
    System.out.println("Reading the plaintext...");
    InputStream plaintextStream = new FileInputStream(Paths.get(plaintextFilename).toFile());
    byte[] plaintext = getStreamContents(plaintextStream);
    plaintextStream.close();

    // Compute the ciphertext and write it to the output file.
    System.out.println("Encrypting...");
    byte[] ciphertext = hybridEncrypt.encrypt(
        plaintext, contextInfo.getBytes(Charset.forName("UTF-8")));
    System.out.println("Writing the ciphertext...");
    OutputStream outputStream = new FileOutputStream(Paths.get(outputFilename).toFile());
    outputStream.write(ciphertext);
    outputStream.close();
    System.out.println("All done.");
  }
}
