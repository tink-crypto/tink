// Copyright 2018 Google Inc.
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
import com.google.crypto.tink.Mac;
import java.security.GeneralSecurityException;

/**
 * A command-line utility for testing Mac-primitives.
 * It requires 4 for MAC computation and 5 for MAC verification:
 *   keyset-file:  name of the file with the keyset to be used for MAC
 *   operation: the actual MAC-operation, i.e. "compute" or "verify"
 *   data-file:  name of the file with data for MAC computation/verification
 *   mac-file:  name of the file for MAC value (when computing the MAC),
 *              or with MAC value (when verifying the MAC)
 *   result-file: name of the file for MAC verification result (valid/invalid)
 *                (only for MAC verification operation)
 */
public class MacCli {
  public static void main(String[] args) throws Exception {
    if (args.length != 4 && args.length != 5) {
      System.out.println(
          "Usage: MacCli keyset-file operation data-file mac-file [result-file]");
      System.exit(1);
    }
    String keysetFilename = args[0];
    String operation = args[1];
    String dataFilename = args[2];
    String macFilename = args[3];
    String resultFilename = "";
    if (!(operation.equals("compute") || operation.equals("verify"))) {
      System.out.println(
          "Unknown operation '" + operation + "'.\nExpected 'compute' or 'verify'.");
      System.exit(1);
    }
    if (operation.equals("compute")) {
      System.out.println("Using keyset from file " + keysetFilename
          + " to compute MAC of data from file " + dataFilename);
      System.out.println("The resulting MAC will be written to file " + macFilename);
    } else {  // operation.equals("verify")
      resultFilename = args[4];
      System.out.println("Using keyset from file " + keysetFilename
          + " to verify MAC value from file " + macFilename
          + " computed for data from file " + dataFilename);
      System.out.println("The verification result will be written to file " + resultFilename);
    }

    // Init Tink.
    CliUtil.initTink();

    // Read the keyset.
    System.out.println("Reading the keyset...");
    KeysetHandle keysetHandle = CliUtil.readKeyset(keysetFilename);

    // Get the primitive.
    System.out.println("Getting the primitive...");
    Mac mac = keysetHandle.getPrimitive(Mac.class);

    // Read the data.
    byte[] data = CliUtil.read(dataFilename);

    // Compute and write the output.
    if (operation.equals("compute")) {
      System.out.println("computing MAC...");
      byte[] macValue;
      macValue = mac.computeMac(data);
      CliUtil.write(macValue, macFilename);
    } else { // operation.equals("verify")
      System.out.println("verifying MAC...");
      byte[] macValue = CliUtil.read(macFilename);
      String result = "valid";
      try {
        mac.verifyMac(macValue, data);
      } catch (GeneralSecurityException e) {
        System.out.println("Verification failed: " + e);
        result = "invalid";
      }
      CliUtil.write(result.getBytes(CliUtil.UTF_8), resultFilename);
    }

    System.out.println("All done.");
  }
}
