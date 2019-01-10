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
import com.google.crypto.tink.PublicKeySign;

/**
 * A command-line utility for testing PublicKeySign-primitives.
 * It requires 3 arguments:
 *   keyset-file:  name of the file with the keyset to be used for signing
 *   message-file:  name of the file that contains message to be signed
 *   output-file:  name of the output file for the resulting plaintext
 */
public class PublicKeySignCli {
  public static void main(String[] args) throws Exception {
    if (args.length != 3) {
      System.out.println(
          "Usage: PublicKeySignCli keyset-file message-file output-file");
      System.exit(1);
    }
    String keysetFilename = args[0];
    String messageFilename = args[1];
    String outputFilename = args[2];
    System.out.println("Using keyset from file " + keysetFilename
        + " to sign message from " + messageFilename + ".");
    System.out.println("The resulting signature will be written to file " + outputFilename);

    // Init Tink.
    CliUtil.initTink();

    // Read the keyset.
    System.out.println("Reading the keyset...");
    KeysetHandle keysetHandle = CliUtil.readKeyset(keysetFilename);

    // Get the primitive.
    System.out.println("Getting the primitive...");
    PublicKeySign pkSign = keysetHandle.getPrimitive(PublicKeySign.class);

    // Read the message.
    byte[] message = CliUtil.read(messageFilename);

    // Compute the signature.
    System.out.println("Signing...");
    byte[] signature = pkSign.sign(message);

    // Write the signature to the output file.
    CliUtil.write(signature, outputFilename);

    System.out.println("All done.");
  }
}
