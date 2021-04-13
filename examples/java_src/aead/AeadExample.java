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
// [START aead-example]
package aead;

import static java.nio.charset.StandardCharsets.UTF_8;

import com.google.crypto.tink.Aead;
import com.google.crypto.tink.CleartextKeysetHandle;
import com.google.crypto.tink.JsonKeysetReader;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.aead.AeadConfig;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.security.GeneralSecurityException;

/**
 * A command-line utility for encrypting small files with AEAD.
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
public final class AeadExample {
  private static final String MODE_ENCRYPT = "encrypt";
  private static final String MODE_DECRYPT = "decrypt";

  public static void main(String[] args) throws Exception {
    if (args.length != 4 && args.length != 5) {
      System.err.printf("Expected 4 or 5 parameters, got %d\n", args.length);
      System.err.println(
          "Usage: java AeadExample encrypt/decrypt key-file input-file output-file"
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
    // Register all AEAD key types with the Tink runtime.
    AeadConfig.register();

    // Read the keyset into a KeysetHandle.
    KeysetHandle handle = null;
    try {
      handle = CleartextKeysetHandle.read(JsonKeysetReader.withFile(keyFile));
    } catch (GeneralSecurityException | IOException ex) {
      System.err.println("Cannot read keyset, got error: " + ex);
      System.exit(1);
    }

    // Get the primitive.
    Aead aead = null;
    try {
      aead = handle.getPrimitive(Aead.class);
    } catch (GeneralSecurityException ex) {
      System.err.println("Cannot create primitive, got error: " + ex);
      System.exit(1);
    }

    // Use the primitive to encrypt/decrypt files.
    if (MODE_ENCRYPT.equals(mode)) {
      byte[] plaintext = Files.readAllBytes(inputFile.toPath());
      byte[] ciphertext = aead.encrypt(plaintext, associatedData);
      try (FileOutputStream stream = new FileOutputStream(outputFile)) {
        stream.write(ciphertext);
      }
    } else if (MODE_DECRYPT.equals(mode)) {
      byte[] ciphertext = Files.readAllBytes(inputFile.toPath());
      byte[] plaintext = aead.decrypt(ciphertext, associatedData);
      try (FileOutputStream stream = new FileOutputStream(outputFile)) {
        stream.write(plaintext);
      }
    } else {
      System.err.println("The first argument must be either encrypt or decrypt, got: " + mode);
      System.exit(1);
    }

    System.exit(0);
  }

  private AeadExample() {}
}
// [END aead-example]
