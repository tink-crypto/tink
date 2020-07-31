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
import com.google.crypto.tink.prf.PrfSet;
import java.io.StringWriter;

/**
 * A command-line utility for testing PrfSet-primitives. It requires 4 arguments: keyset-file: name
 * of the file with the keyset to be used for PrfSet data-file: name of the file with data for
 * PrfSet input result-file: name of the file for PrfSet output. output-length: length of the prf
 * output in bytes. Format of the output set: <prf_id>:hexencode(<prf_output>) where <prf_id> is the
 * uint32 decimal representation of the ID of the PRF. If the requested output is too long the
 * result should be instead <prf_id>:--. The file is sorted by <prf_id> in the shell script.
 */
public class PrfSetCli {
  public static void main(String[] args) throws Exception {
    if (args.length != 4) {
      System.out.println("Usage: PrfSetCli keyset-file data-file result-file output_length");
      System.exit(1);
    }
    String keysetFilename = args[0];
    String dataFilename = args[1];
    String resultFilename = args[2];
    int outputLength = Integer.parseInt(args[3]);
    System.out.println(
        "Using keyset from file "
            + keysetFilename
            + " to compute PRFs of data from file "
            + dataFilename);
    System.out.println("The resulting PRFs will be written to file " + resultFilename);

    // Init Tink.
    CliUtil.initTink();

    // Read the keyset.
    System.out.println("Reading the keyset...");
    KeysetHandle keysetHandle = CliUtil.readKeyset(keysetFilename);

    // Get the primitive.
    System.out.println("Getting the primitive...");
    PrfSet prfSet = keysetHandle.getPrimitive(PrfSet.class);

    // Read the data.
    byte[] data = CliUtil.read(dataFilename);

    // Compute and write the output.
    System.out.println("computing PRF...");
    StringWriter out = new StringWriter();
    for (int id : prfSet.getPrfs().keySet()) {
      out.write((toUnsignedInt32(id) + ":"));
      try {
        byte[] prfValue = prfSet.getPrfs().get(id).compute(data, outputLength);
        out.write(TestUtil.hexEncode(prfValue));
      } catch (Exception e) {
        out.write("--");
      }
      out.write("\n");
    }
    CliUtil.write(out.toString().getBytes(CliUtil.UTF_8), resultFilename);

    System.out.println("All done.");
  }

  private static long toUnsignedInt32(int id) {
    return ((long) id) & 0xffffffffL;
  }

  private PrfSetCli() {}
}
