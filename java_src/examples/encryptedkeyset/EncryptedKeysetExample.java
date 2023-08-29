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
// [START encrypted-keyset-example]
package encryptedkeyset;

import static java.nio.charset.StandardCharsets.UTF_8;

import com.google.crypto.tink.Aead;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.TinkJsonProtoKeysetFormat;
import com.google.crypto.tink.aead.AeadConfig;
import com.google.crypto.tink.aead.PredefinedAeadParameters;
import com.google.crypto.tink.integration.gcpkms.GcpKmsClient;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

/**
 * A command-line utility for working with encrypted keysets.
 *
 * <p>It requires the following arguments:
 *
 * <ul>
 *   <li>mode: Can be "generate", "encrypt" or "decrypt". If mode is "generate", it will generate a
 *       keyset, encrypt it and store it in the key-file argument. If mode is "encrypt" or
 *       "decrypt", it will read and decrypt an keyset from the key-file argument, and use it to
 *       encrypt or decrypt the input-file argument.
 *   <li>kek-uri: Use this Cloud KMS' key as the key-encrypting-key for envelope encryption.
 *   <li>gcp-credential-file: Use this JSON credential file to connect to Cloud KMS.
 *   <li>input-file: If mode is "encrypt" or "decrypt", read the input from this file.
 *   <li>output-file: If mode is "encrypt" or "decrypt", write the result to this file.
 */
public final class EncryptedKeysetExample {
  private static final String MODE_ENCRYPT = "encrypt";
  private static final String MODE_DECRYPT = "decrypt";
  private static final String MODE_GENERATE = "generate";
  private static final byte[] EMPTY_ASSOCIATED_DATA = new byte[0];

  public static void main(String[] args) throws Exception {
    if (args.length != 4 && args.length != 6) {
      System.err.printf("Expected 4 or 6 parameters, got %d\n", args.length);
      System.err.println(
          "Usage: java EncryptedKeysetExample generate/encrypt/decrypt key-file kek-uri"
              + " gcp-credential-file input-file output-file");
      System.exit(1);
    }
    String mode = args[0];
    if (!mode.equals(MODE_ENCRYPT) && !mode.equals(MODE_DECRYPT) && !mode.equals(MODE_GENERATE)) {
      System.err.print("The first argument should be either encrypt, decrypt or generate");
      System.exit(1);
    }
    Path keyFile = Paths.get(args[1]);
    String kekUri = args[2];
    String gcpCredentialFilename = args[3];

    // Initialise Tink: register all AEAD key types with the Tink runtime
    AeadConfig.register();

    // From the key-encryption key (KEK) URI, create a remote AEAD primitive for encrypting Tink
    // keysets.
    Aead kekAead = new GcpKmsClient().withCredentials(gcpCredentialFilename).getAead(kekUri);

    if (mode.equals(MODE_GENERATE)) {
      // [START generate-a-new-keyset]
      KeysetHandle handle = KeysetHandle.generateNew(PredefinedAeadParameters.AES128_GCM);
      // [END generate-a-new-keyset]

      // [START encrypt-a-keyset]
      String serializedEncryptedKeyset =
          TinkJsonProtoKeysetFormat.serializeEncryptedKeyset(
              handle, kekAead, EMPTY_ASSOCIATED_DATA);
      Files.write(keyFile, serializedEncryptedKeyset.getBytes(UTF_8));
      // [END encrypt-a-keyset]
      return;
    }

    // Use the primitive to encrypt/decrypt files

    // Read the encrypted keyset
    KeysetHandle handle =
        TinkJsonProtoKeysetFormat.parseEncryptedKeyset(
            new String(Files.readAllBytes(keyFile), UTF_8), kekAead, EMPTY_ASSOCIATED_DATA);

    // Get the primitive
    Aead aead = handle.getPrimitive(Aead.class);

    Path inputFile = Paths.get(args[4]);
    Path outputFile = Paths.get(args[5]);

    if (mode.equals(MODE_ENCRYPT)) {
      byte[] plaintext = Files.readAllBytes(inputFile);
      byte[] ciphertext = aead.encrypt(plaintext, EMPTY_ASSOCIATED_DATA);
      Files.write(outputFile, ciphertext);
    } else if (mode.equals(MODE_DECRYPT)) {
      byte[] ciphertext = Files.readAllBytes(inputFile);
      byte[] plaintext = aead.decrypt(ciphertext, EMPTY_ASSOCIATED_DATA);
      Files.write(outputFile, plaintext);
    }
  }

  private EncryptedKeysetExample() {}
}
// [END encrypted-keyset-example]
