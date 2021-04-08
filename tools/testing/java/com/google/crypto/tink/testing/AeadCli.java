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

import com.google.crypto.tink.Aead;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.aead.AeadConfig;
import com.google.crypto.tink.integration.awskms.AwsKmsClient;
import com.google.crypto.tink.integration.gcpkms.GcpKmsClient;
import java.util.Optional;

/**
 * A command-line utility for testing Aead-primitives. It requires 5 arguments: keyset-file: name of
 * the file with the keyset to be used for encryption operation: the actual AEAD-operation, i.e.
 * "encrypt" or "decrypt" input-file: name of the file with input (plaintext for encryption, or or
 * ciphertext for decryption) associated-data-file: name of the file containing associated data
 * output-file: name of the file for the resulting output
 */
public class AeadCli {
  public static void main(String[] args) throws Exception {

    if (args.length != 5) {
      System.out.println(
          "Usage: AeadCli keyset-file operation input-file associated-data-file output-file");
      System.exit(1);
    }
    String keysetFilename = args[0];
    String operation = args[1];
    String inputFilename = args[2];
    String associatedDataFile = args[3];
    String outputFilename = args[4];

    GcpKmsClient.register(Optional.empty(), Optional.of("../tink_base/" + TestUtil.SERVICE_ACCOUNT_FILE));
    AwsKmsClient.register(Optional.of(TestUtil.AWS_CRYPTO_URI), Optional.of("../tink_base/" + TestUtil.AWS_CREDS));
    AeadConfig.register();

    if (!(operation.equals("encrypt") || operation.equals("decrypt"))) {
      System.out.println(
          "Unknown operation '" + operation + "'.\nExpected 'encrypt' or 'decrypt'.");
      System.exit(1);
    }
    System.out.println("Using keyset from file " + keysetFilename + " to AEAD-" + operation
        + " file " + inputFilename + " with associated data from file " + associatedDataFile + ".");
    System.out.println("The resulting output will be written to file " + outputFilename);

    // Init Tink.
    CliUtil.initTink();

    // Read the keyset.
    System.out.println("Reading the keyset...");
    KeysetHandle keysetHandle = CliUtil.readKeyset(keysetFilename);
    // Get the primitive.
    System.out.println("Getting the primitive...");
    Aead aead = keysetHandle.getPrimitive(Aead.class);

    // Read the input.
    byte[] input = CliUtil.read(inputFilename);
    byte[] aad = CliUtil.read(associatedDataFile);

    // Compute the output.
    System.out.println(operation + "ing...");
    byte[] output;
    if (operation.equals("encrypt")) {
      output = aead.encrypt(input, aad);
    } else { // operation.equals("decrypt")
      output = aead.decrypt(input, aad);
    }
    // Write the output to the output file.
    CliUtil.write(output, outputFilename);

    System.out.println("All done.");
  }

  private AeadCli() {}
}
