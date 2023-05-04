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

import com.google.crypto.tink.HybridDecrypt;
import com.google.crypto.tink.HybridEncrypt;
import com.google.crypto.tink.InsecureSecretKeyAccess;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.TinkJsonProtoKeysetFormat;
import com.google.crypto.tink.hybrid.HybridConfig;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

/**
 * A command-line utility for hybrid encryption.
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
    Path keyFile = Paths.get(args[1]);
    Path inputFile = Paths.get(args[2]);
    byte[] input = Files.readAllBytes(inputFile);
    Path outputFile = Paths.get(args[3]);
    byte[] contextInfo = new byte[0];
    if (args.length == 5) {
      contextInfo = args[4].getBytes(UTF_8);
    }

    // Register all hybrid encryption key types with the Tink runtime.
    HybridConfig.register();

    // Read the keyset into a KeysetHandle.
    KeysetHandle handle =
        TinkJsonProtoKeysetFormat.parseKeyset(
            new String(Files.readAllBytes(keyFile), UTF_8), InsecureSecretKeyAccess.get());

    if (mode.equals("encrypt")) {
      // Get the primitive.
      HybridEncrypt encryptor = handle.getPrimitive(HybridEncrypt.class);

      // Use the primitive to encrypt data.
      byte[] ciphertext = encryptor.encrypt(input, contextInfo);
      Files.write(outputFile, ciphertext);
    } else {
      HybridDecrypt decryptor = handle.getPrimitive(HybridDecrypt.class);

      // Use the primitive to decrypt data.
      byte[] plaintext = decryptor.decrypt(input, contextInfo);
      Files.write(outputFile, plaintext);
    }
  }

  private HybridExample() {}
}
// [END hybrid-example]
