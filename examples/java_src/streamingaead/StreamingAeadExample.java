/**
 * Copyright 2021 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License
 * is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express
 * or implied. See the License for the specific language governing permissions and limitations under
 * the License.
 */
// [START streaming-aead-example]
package streamingaead;

import static java.nio.charset.StandardCharsets.UTF_8;

import com.google.crypto.tink.CleartextKeysetHandle;
import com.google.crypto.tink.JsonKeysetReader;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.StreamingAead;
import com.google.crypto.tink.streamingaead.StreamingAeadConfig;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.GeneralSecurityException;

/**
 * A command-line utility for encrypting files with Streaming AEAD.
 *
 * <p>It loads cleartext keys from disk - this is not recommended!
 *
 * <p>It requires the following arguments:
 *
 * <ul>
 *   <li>mode: Can be "encrypt" or "decrypt" to encrypt/decrypt the input to the output.
 *   <li>key-file: Read the key material from this file.
 *   <li>input-file: Read the input from this file.
 *   <li>output-file: Write the result to this file.
 *   <li>[optional] associated-data: Associated data used for the encryption or decryption.
 */
public final class StreamingAeadExample {
  private static final String MODE_ENCRYPT = "encrypt";
  private static final String MODE_DECRYPT = "decrypt";

  public static void main(String[] args) throws Exception {
    if (args.length != 4 && args.length != 5) {
      System.err.printf("Expected 4 or 5 parameters, got %d\n", args.length);
      System.err.println(
          "Usage: java StreamingAeadExample encrypt/decrypt key-file input-file output-file"
              + " [associated-data]");
      System.exit(1);
    }
    String mode = args[0];
    File keyFile = new File(args[1]);
    File inputFile = new File(args[2]);
    File outputFile = new File(args[3]);
    byte[] associatedData = new byte[0];
    if (args.length == 5) {
      associatedData = args[4].getBytes(UTF_8);
    }

    // Initalise Tink: register all Streaming AEAD key types with the Tink runtime
    StreamingAeadConfig.register();

    // Read the keyset into a KeysetHandle
    KeysetHandle handle = null;
    try {
      handle = CleartextKeysetHandle.read(JsonKeysetReader.withFile(keyFile));
    } catch (GeneralSecurityException | IOException ex) {
      System.err.println("Cannot read keyset, got error: " + ex);
      System.exit(1);
    }

    // Get the primitive
    StreamingAead streamingAead = null;
    try {
      streamingAead = handle.getPrimitive(StreamingAead.class);
    } catch (GeneralSecurityException ex) {
      System.err.println("Cannot create primitive, got error: " + ex);
      System.exit(1);
    }

    // Use the primitive to encrypt/decrypt files
    if (MODE_ENCRYPT.equals(mode)) {
      encryptFile(streamingAead, inputFile, outputFile, associatedData);
    } else if (MODE_DECRYPT.equals(mode)) {
      decryptFile(streamingAead, inputFile, outputFile, associatedData);
    } else {
      System.err.println("The first argument must be either encrypt or decrypt, got: " + mode);
      System.exit(1);
    }

    System.exit(0);
  }

  private static void encryptFile(
      StreamingAead streamingAead, File inputFile, File outputFile, byte[] associatedData)
      throws GeneralSecurityException, IOException {
    try (OutputStream ciphertextStream =
            streamingAead.newEncryptingStream(new FileOutputStream(outputFile), associatedData);
        InputStream plaintextStream = new FileInputStream(inputFile)) {
      byte[] chunk = new byte[1024];
      int chunkLen = 0;
      while ((chunkLen = plaintextStream.read(chunk)) != -1) {
        ciphertextStream.write(chunk, 0, chunkLen);
      }
    }
  }

  private static void decryptFile(
      StreamingAead streamingAead, File inputFile, File outputFile, byte[] associatedData)
      throws GeneralSecurityException, IOException {
    InputStream ciphertextStream =
        streamingAead.newDecryptingStream(new FileInputStream(inputFile), associatedData);

    OutputStream plaintextStream = new FileOutputStream(outputFile);
    byte[] chunk = new byte[1024];
    int chunkLen = 0;
    while ((chunkLen = ciphertextStream.read(chunk)) != -1) {
      plaintextStream.write(chunk, 0, chunkLen);
    }

    ciphertextStream.close();
    plaintextStream.close();
  }

  private StreamingAeadExample() {}
}
// [END streaming-aead-example]
