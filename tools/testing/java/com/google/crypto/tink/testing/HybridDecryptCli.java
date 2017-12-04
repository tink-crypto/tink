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

import com.google.crypto.tink.HybridDecrypt;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.hybrid.HybridDecryptFactory;

/**
 * A command-line utility for testing HybridDecrypt-primitives.
 * It requires 4 arguments:
 *  keyset-file:  name of the file with the keyset to be used for decryption
 *  ciphertext-file:  name of the file that contains ciphertext to be decrypted
 *  context-info:  a string to be used as "context info" during the decryption
 *  output-file:  name of the output file for the resulting ciphertext
 */
public class HybridDecryptCli {
  public static void main(String[] args) throws Exception {
    if (args.length != 4) {
      System.out.println(
          "Usage: HybridDecryptCli keyset-file ciphertext-file context-info output-file");
      System.exit(1);
    }
    String keysetFilename = args[0];
    String ciphertextFilename = args[1];
    String contextInfo = args[2];
    String outputFilename = args[3];
    System.out.println("Using keyset from file " + keysetFilename + " to decrypt file "
        + ciphertextFilename + " with context info '" + contextInfo + "'.");
    System.out.println("The resulting plaintext will be written to file " + outputFilename);

    // Init Tink.
    CliUtil.initTink();

    // Read the keyset.
    System.out.println("Reading the keyset...");
    KeysetHandle keysetHandle = CliUtil.readKeyset(keysetFilename);

    // Get the primitive.
    System.out.println("Getting the primitive...");
    HybridDecrypt hybridDecrypt = HybridDecryptFactory.getPrimitive(keysetHandle);

    // Read the ciphertext.
    byte[] ciphertext = CliUtil.read(ciphertextFilename);

    // Compute the plaintext.
    System.out.println("Decrypting...");
    byte[] plaintext = hybridDecrypt.decrypt(ciphertext, contextInfo.getBytes(CliUtil.UTF_8));

    // Write the plaintext to the output file.
    CliUtil.write(plaintext, outputFilename);

    System.out.println("All done.");
  }
}
