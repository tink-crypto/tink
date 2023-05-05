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

import com.google.crypto.tink.InsecureSecretKeyAccess;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.StreamingAead;
import com.google.crypto.tink.TinkJsonProtoKeysetFormat;
import com.google.crypto.tink.streamingaead.StreamingAeadConfig;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.channels.ReadableByteChannel;
import java.nio.channels.WritableByteChannel;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
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
  private static final int BLOCK_SIZE_IN_BYTES = 8 * 1024;

  public static void main(String[] args) throws Exception {
    if (args.length != 4 && args.length != 5) {
      System.err.printf("Expected 4 or 5 parameters, got %d\n", args.length);
      System.err.println(
          "Usage: java StreamingAeadExample encrypt/decrypt key-file input-file output-file"
              + " [associated-data]");
      System.exit(1);
    }
    String mode = args[0];
    Path keyFile = Paths.get(args[1]);
    Path inputFile = Paths.get(args[2]);
    Path outputFile = Paths.get(args[3]);
    byte[] associatedData = new byte[0];
    if (args.length == 5) {
      associatedData = args[4].getBytes(UTF_8);
    }

    // Initalise Tink: register all Streaming AEAD key types with the Tink runtime
    StreamingAeadConfig.register();

    // Read the keyset into a KeysetHandle
    KeysetHandle handle =
        TinkJsonProtoKeysetFormat.parseKeyset(
            new String(Files.readAllBytes(keyFile), UTF_8), InsecureSecretKeyAccess.get());

    // Get the primitive
    StreamingAead streamingAead = handle.getPrimitive(StreamingAead.class);

    // Use the primitive to encrypt/decrypt files
    if (MODE_ENCRYPT.equals(mode)) {
      encryptFile(streamingAead, inputFile, outputFile, associatedData);
    } else if (MODE_DECRYPT.equals(mode)) {
      decryptFile(streamingAead, inputFile, outputFile, associatedData);
    } else {
      System.err.println("The first argument must be either encrypt or decrypt, got: " + mode);
      System.exit(1);
    }
  }

  private static void encryptFile(
      StreamingAead streamingAead, Path inputFile, Path outputFile, byte[] associatedData)
      throws GeneralSecurityException, IOException {
    try (WritableByteChannel plaintextChannel =
            streamingAead.newEncryptingChannel(
                FileChannel.open(outputFile, StandardOpenOption.WRITE, StandardOpenOption.CREATE),
                associatedData);
        FileChannel inputChannel = FileChannel.open(inputFile, StandardOpenOption.READ)) {
      ByteBuffer byteBuffer = ByteBuffer.allocate(BLOCK_SIZE_IN_BYTES);
      while (true) {
        int read = inputChannel.read(byteBuffer);
        if (read <= 0) {
          return;
        }
        byteBuffer.flip();
        while (byteBuffer.hasRemaining()) {
          plaintextChannel.write(byteBuffer);
        }
        byteBuffer.clear();
      }
    }
  }

  private static void decryptFile(
      StreamingAead streamingAead, Path inputFile, Path outputFile, byte[] associatedData)
      throws GeneralSecurityException, IOException {
    try (ReadableByteChannel plaintextChannel =
            streamingAead.newDecryptingChannel(
                FileChannel.open(inputFile, StandardOpenOption.READ), associatedData);
        FileChannel outputChannel =
            FileChannel.open(outputFile, StandardOpenOption.WRITE, StandardOpenOption.CREATE)) {
      ByteBuffer byteBuffer = ByteBuffer.allocate(BLOCK_SIZE_IN_BYTES);
      while (true) {
        int read = plaintextChannel.read(byteBuffer);
        if (read <= 0) {
          return;
        }
        byteBuffer.flip();
        while (byteBuffer.hasRemaining()) {
          outputChannel.write(byteBuffer);
        }
        byteBuffer.clear();
      }
    }
  }

  private StreamingAeadExample() {}
}
// [END streaming-aead-example]
