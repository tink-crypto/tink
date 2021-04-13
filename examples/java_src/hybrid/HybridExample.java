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
// [START hybrid-example]
package hybrid;

import static java.nio.charset.StandardCharsets.UTF_8;

import com.google.crypto.tink.CleartextKeysetHandle;
import com.google.crypto.tink.HybridDecrypt;
import com.google.crypto.tink.HybridEncrypt;
import com.google.crypto.tink.JsonKeysetReader;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.hybrid.HybridConfig;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.security.GeneralSecurityException;

/**
 * A command-line utility for digitally signing and verifying a file.
 *
 * <p>It loads cleartext keys from disk - this is not recommended!
 *
 * <p>It requires the following arguments:
 *
 * <ul>
 *   <li>mode: either 'encrypt' or 'decrypt'.
 *   <li>key-file: Read the key material from this file.
 *   <li>input-file: Read the input from this file.
 *   <li>output-file: Write the result to this file.
 *   <li>[optional] contex-info: Bind the encryption to this context info.
 */
public final class HybridExample {
  public static void main(String[] args) throws Exception {
    if (args.length != 4 && args.length != 5) {
      System.err.printf("Expected 4 or 5 parameters, got %d\n", args.length);
      System.err.println(
          "Usage: java HybridExample encrypt/decrypt key-file input-file output-file context-info");
      System.exit(1);
    }

    String mode = args[0];
    if (!mode.equals("encrypt") && !mode.equals("decrypt")) {
      System.err.println("Incorrect mode. Please select encrypt or decrypt.");
      System.exit(1);
    }
    File keyFile = new File(args[1]);
    File inputFile = new File(args[2]);
    byte[] input = Files.readAllBytes(inputFile.toPath());
    File outputFile = new File(args[3]);
    byte[] contextInfo = new byte[0];
    if (args.length == 5) {
      contextInfo = args[4].getBytes(UTF_8);
    }

    // Register all hybrid encryption key types with the Tink runtime.
    HybridConfig.register();

    // Read the keyset into a KeysetHandle.
    KeysetHandle handle = null;
    try {
      handle = CleartextKeysetHandle.read(JsonKeysetReader.withFile(keyFile));
    } catch (GeneralSecurityException | IOException ex) {
      System.err.println("Cannot read keyset, got error: " + ex);
      System.exit(1);
    }

    if (mode.equals("encrypt")) {
      // Get the primitive.
      HybridEncrypt encryptor = null;
      try {
        encryptor = handle.getPrimitive(HybridEncrypt.class);
      } catch (GeneralSecurityException ex) {
        System.err.println("Cannot create primitive, got error: " + ex);
        System.exit(1);
      }

      // Use the primitive to encrypt data.
      byte[] ciphertext = encryptor.encrypt(input, contextInfo);
      try (FileOutputStream stream = new FileOutputStream(outputFile)) {
        stream.write(ciphertext);
      }
      System.exit(0);
    }

    // Get the primitive.
    HybridDecrypt decryptor = null;
    try {
      decryptor = handle.getPrimitive(HybridDecrypt.class);
    } catch (GeneralSecurityException ex) {
      System.err.println("Cannot create primitive, got error: " + ex);
      System.exit(1);
    }

    // Use the primitive to decrypt data.
    byte[] plaintext = decryptor.decrypt(input, contextInfo);
    try (FileOutputStream stream = new FileOutputStream(outputFile)) {
      stream.write(plaintext);
    }
    System.exit(0);
  }

  private HybridExample() {}
}
// [END hybrid-example]
