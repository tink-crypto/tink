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
import com.google.crypto.tink.StreamingAead;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.PipedInputStream;
import java.io.PipedOutputStream;
import java.nio.file.Paths;
import java.security.GeneralSecurityException;

/**
 * A command-line utility for testing StreamingAead-primitives.
 * It requires 5 arguments:
 *   keyset-file:  name of the file with the keyset to be used for encryption
 *   operation: the actual Streaming AEAD-operation, i.e. "encrypt" or "decrypt"
 *   input-file:  name of the file with input (plaintext for encryption, or
 *                or ciphertext for decryption)
 *   associated-data-file:  name of the file containing associated data
 *   output-file:  name of the file for the resulting output
 */
public class StreamingAeadCli {


  /**
   * Returns an InputStream that provides ciphertext resulting from encryption
   * of 'plaintextStream' with 'associatedData' via 'streamingAead'.
   *
   * This method demonstrates how to "invert" the direction of the encrypting
   * stream, which might be required in some use cases:
   *
   * {@code StreamingAead.newEncryptingStream()} expects as parameter an
   * OutputStream for the resulting ciphertext ({@code ciphertextDestination}),
   * and returns an OutputStream to which the plaintext can be written.
   * The plaintext to this OutputStream is automatically encrypted and
   * the corresponding ciphertext is written to the ciphertext destination.
   *
   * Sometimes however the plaintext for encryption might be given
   * in an InputStream and the desired encrypting stream should be also
   * an InputStream (ciphertextSource), such that each read from this
   * stream automatically reads from the plaintext stream, encrypts the
   * the plaintext bytes, and returns the corresponding ciphertext bytes.
   *
   * NOTE: this method is for demonstration only, and should be adjusted
   *       to specific needs. In particular, the handling of potential
   *       exceptions via a RuntimeException might be not suitable.
   */
  public static InputStream getCiphertextStream(final StreamingAead streamingAead,
      final InputStream plaintextStream, final byte[] associatedData)
      throws IOException {

    PipedInputStream ciphertextStream = new PipedInputStream();
    final PipedOutputStream outputStream = new PipedOutputStream(ciphertextStream);
    new Thread(new Runnable() {
        @Override
        public void run(){
          try (OutputStream encryptingStream =
              streamingAead.newEncryptingStream(outputStream, associatedData)) {
            byte[] buffer = new byte[1024];
            int length;
            while ((length = plaintextStream.read(buffer)) != -1) {
              encryptingStream.write(buffer, 0, length);
            }
            plaintextStream.close();
          } catch (GeneralSecurityException | IOException e) {
            throw new RuntimeException("Stream encryption failure.", e);
          }
        }
      }
      ).start();
    return ciphertextStream;
  }

  public static void main(String[] args) throws Exception {
    if (args.length != 5) {
      System.out.println("Usage: StreamingAeadCli"
          + " keyset-file operation input-file associated-data-file output-file");
      System.exit(1);
    }
    String keysetFilename = args[0];
    String operation = args[1];
    String inputFilename = args[2];
    String associatedDataFile = args[3];
    String outputFilename = args[4];
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
    StreamingAead streamingAead = keysetHandle.getPrimitive(StreamingAead.class);

    // Read the input.
    InputStream inputStream = new FileInputStream(Paths.get(inputFilename).toFile());
    byte[] aad = CliUtil.read(associatedDataFile);

    // Compute the output.
    System.out.println(operation + "ing...");
    byte[] output;
    if (operation.equals("encrypt")) {
      InputStream ciphertextStream = getCiphertextStream(streamingAead, inputStream, aad);
      output = CliUtil.read(ciphertextStream);
    } else { // operation.equals("decrypt")
      InputStream plaintextStream = streamingAead.newDecryptingStream(inputStream, aad);
      output = CliUtil.read(plaintextStream);
    }

    // Write the output to the output file.
    CliUtil.write(output, outputFilename);

    System.out.println("All done.");
  }
}
