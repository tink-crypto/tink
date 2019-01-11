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

import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.PublicKeyVerify;
import java.security.GeneralSecurityException;

/**
 * A command-line utility for testing PublicKeyVerify-primitives.
 * It requires 4 arguments:
 *   keyset-file:  name of the file with the keyset to be used for verifying
 *   signature-file:  name of the file that contains the signature
 *   message-file:  name of the file that contains message to be verified
 *   output-file:  name of the output file for the verification result (valid/invalid)
 */
public class PublicKeyVerifyCli {
  public static void main(String[] args) throws Exception {
    if (args.length != 4) {
      System.out.println(
          "Usage: PublicKeyVerifyCli keyset-file signature-file message-file output-file");
      System.exit(1);
    }
    String keysetFilename = args[0];
    String signatureFilename = args[1];
    String messageFilename = args[2];
    String outputFilename = args[3];
    System.out.println("Using keyset from file " + keysetFilename
        + " to verify signature from file " + signatureFilename
        + " of the message from file " + messageFilename + ".");
    System.out.println("The verification result will be written to file " + outputFilename);

    // Init Tink.
    CliUtil.initTink();

    // Read the keyset.
    System.out.println("Reading the keyset...");
    KeysetHandle keysetHandle = CliUtil.readKeyset(keysetFilename);

    // Get the primitive.
    System.out.println("Getting the primitive...");
    PublicKeyVerify pkVerify = keysetHandle.getPrimitive(PublicKeyVerify.class);

    // Read the signature.
    byte[] signature = CliUtil.read(signatureFilename);

    // Read the message.
    byte[] message = CliUtil.read(messageFilename);

    // Verify the signature.
    System.out.println("Verifying...");
    String verificationResult;
    try {
      pkVerify.verify(signature, message);
      verificationResult = "valid";
    } catch (GeneralSecurityException e) {
      System.out.println("Verification failed: " + e);
      verificationResult = "invalid";
    }
    // Write the verification result to the output file.
    CliUtil.write(verificationResult.getBytes(CliUtil.UTF_8), outputFilename);

    System.out.println("All done.");
  }
}
