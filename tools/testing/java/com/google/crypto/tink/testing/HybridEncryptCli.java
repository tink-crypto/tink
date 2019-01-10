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

import com.google.crypto.tink.HybridEncrypt;
import com.google.crypto.tink.KeysetHandle;

/**
 * A command-line utility for testing HybridEncrypt-primitives.
 * It requires 4 arguments:
 * keyset-file:  name of the file with the keyset to be used for encryption
 * plaintext-file:  name of the file that contains plaintext to be encrypted
 * context-info-file:  name of the file that contains "context info" which will
 *     be used during the decryption
 * output-file:  name of the output file for the resulting ciphertext
 */
public class HybridEncryptCli {
  public static void main(String[] args) throws Exception {
    if (args.length != 4) {
      System.out.println(
          "Usage: HybridEncryptCli keyset-file plaintext-file context-info-file output-file");
      System.exit(1);
    }
    String keysetFilename = args[0];
    String plaintextFilename = args[1];
    String contextInfoFilename = args[2];
    String outputFilename = args[3];
    System.out.println("Using keyset from file " + keysetFilename + " to encrypt file "
        + plaintextFilename + " with context info from file " + contextInfoFilename + ".");
    System.out.println("The resulting ciphertext will be written to file " + outputFilename);

    // Init Tink.
    CliUtil.initTink();

    // Read the keyset.
    System.out.println("Reading the keyset...");
    KeysetHandle keysetHandle = CliUtil.readKeyset(keysetFilename);

    // Get the primitive.
    System.out.println("Getting the primitive...");
    HybridEncrypt hybridEncrypt = keysetHandle.getPrimitive(HybridEncrypt.class);

    // Read the plaintext.
    byte[] plaintext = CliUtil.read(plaintextFilename);
    byte[] contextInfo = CliUtil.read(contextInfoFilename);

    // Compute the ciphertext.
    System.out.println("Encrypting...");
    byte[] ciphertext = hybridEncrypt.encrypt(plaintext, contextInfo);

    // Write the ciphertext to the output file.
    CliUtil.write(ciphertext, outputFilename);

    System.out.println("All done.");
  }
}
