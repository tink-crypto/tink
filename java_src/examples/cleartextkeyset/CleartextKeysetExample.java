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
// [START cleartext-keyset-example]
package cleartextkeyset;

import static java.nio.charset.StandardCharsets.UTF_8;

import com.google.crypto.tink.Aead;
import com.google.crypto.tink.InsecureSecretKeyAccess;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.TinkJsonProtoKeysetFormat;
import com.google.crypto.tink.aead.AeadConfig;
import com.google.crypto.tink.aead.PredefinedAeadParameters;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

/**
 * A command-line utility for generating, storing and using AES128_GCM keysets.
 *
 * <h1>WARNING: Loading a Keyset from disk is often a security problem -- hence this needs {@code
 * InsecureSecretKeyAccess.get()}.
 *
 * <p>It requires the following arguments:
 *
 * <ul>
 *   <li>mode: Can be "generate", "encrypt" or "decrypt". If mode is "generate" it will generate,
 *       encrypt a keyset, store it in key-file. If mode is "encrypt" or "decrypt" it will read and
 *       decrypt an keyset from key-file, and use it to encrypt or decrypt input-file.
 *   <li>key-file: Read the encrypted key material from this file.
 *   <li>input-file: If mode is "encrypt" or "decrypt", read the input from this file.
 *   <li>output-file: If mode is "encrypt" or "decrypt", write the result to this file.
 */
public final class CleartextKeysetExample {
  private static final String MODE_ENCRYPT = "encrypt";
  private static final String MODE_DECRYPT = "decrypt";
  private static final String MODE_GENERATE = "generate";
  private static final byte[] EMPTY_ASSOCIATED_DATA = new byte[0];

  public static void main(String[] args) throws Exception {
    if (args.length != 2 && args.length != 4) {
      System.err.printf("Expected 2 or 4 parameters, got %d\n", args.length);
      System.err.println(
          "Usage: java CleartextKeysetExample generate/encrypt/decrypt key-file input-file"
              + " output-file");
      System.exit(1);
    }
    String mode = args[0];
    if (!MODE_ENCRYPT.equals(mode) && !MODE_DECRYPT.equals(mode) && !MODE_GENERATE.equals(mode)) {
      System.err.print("The first argument should be either encrypt, decrypt or generate");
      System.exit(1);
    }
    Path keyFile = Paths.get(args[1]);

    // Initialise Tink: register all AEAD key types with the Tink runtime
    AeadConfig.register();

    if (MODE_GENERATE.equals(mode)) {
      // [START generate-a-new-keyset]
      KeysetHandle handle = KeysetHandle.generateNew(PredefinedAeadParameters.AES128_GCM);
      // [END generate-a-new-keyset]

      // [START store-a-cleartext-keyset]
      String serializedKeyset =
          TinkJsonProtoKeysetFormat.serializeKeyset(handle, InsecureSecretKeyAccess.get());
      Files.write(keyFile, serializedKeyset.getBytes(UTF_8));
      // [END store-a-cleartext-keyset]
      return;
    }

    // Use the primitive to encrypt/decrypt files

    // Read the keyset from disk
    String serializedKeyset = new String(Files.readAllBytes(keyFile), UTF_8);
    KeysetHandle handle =
        TinkJsonProtoKeysetFormat.parseKeyset(serializedKeyset, InsecureSecretKeyAccess.get());

    // Get the primitive
    Aead aead = handle.getPrimitive(Aead.class);

    byte[] input = Files.readAllBytes(Paths.get(args[2]));
    Path outputFile = Paths.get(args[3]);

    if (MODE_ENCRYPT.equals(mode)) {
      byte[] ciphertext = aead.encrypt(input, EMPTY_ASSOCIATED_DATA);
      Files.write(outputFile, ciphertext);
    } else if (MODE_DECRYPT.equals(mode)) {
      byte[] plaintext = aead.decrypt(input, EMPTY_ASSOCIATED_DATA);
      Files.write(outputFile, plaintext);
    }
  }

  private CleartextKeysetExample() {}
}
// [END cleartext-keyset-example]
