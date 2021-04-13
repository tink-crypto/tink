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

import com.google.crypto.tink.Aead;
import com.google.crypto.tink.JsonKeysetReader;
import com.google.crypto.tink.JsonKeysetWriter;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.aead.AeadConfig;
import com.google.crypto.tink.aead.AesGcmKeyManager;
import com.google.crypto.tink.aead.KmsAeadKeyManager;
import com.google.crypto.tink.integration.gcpkms.GcpKmsClient;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.GeneralSecurityException;
import java.util.Optional;

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
    if (!MODE_ENCRYPT.equals(mode) && !MODE_DECRYPT.equals(mode) && !MODE_GENERATE.equals(mode)) {
      System.err.print("The first argument should be either encrypt, decrypt or generate");
      System.exit(1);
    }
    File keyFile = new File(args[1]);
    String kekUri = args[2];
    String gcpCredentialFilename = args[3];

    // Initialise Tink: register all AEAD key types with the Tink runtime
    AeadConfig.register();

    // Read the GCP credentials and set up client
    try {
      GcpKmsClient.register(Optional.of(kekUri), Optional.of(gcpCredentialFilename));
    } catch (GeneralSecurityException ex) {
      System.err.println("Error initializing GCP client: " + ex);
      System.exit(1);
    }

    // From the key-encryption key (KEK) URI, create a remote AEAD primitive for encrypting Tink
    // keysets.
    Aead kekAead = null;
    try {
      KeysetHandle handle = KeysetHandle.generateNew(KmsAeadKeyManager.createKeyTemplate(kekUri));
      kekAead = handle.getPrimitive(Aead.class);
    } catch (GeneralSecurityException ex) {
      System.err.println("Error creating primitive: %s " + ex);
      System.exit(1);
    }

    if (MODE_GENERATE.equals(mode)) {
      // [START generate-a-new-keyset]
      KeysetHandle handle = KeysetHandle.generateNew(AesGcmKeyManager.aes128GcmTemplate());
      // [END generate-a-new-keyset]

      // [START encrypt-a-keyset]
      handle.write(JsonKeysetWriter.withFile(keyFile), kekAead);
      // [END encrypt-a-keyset]
      System.exit(0);
    }

    // Use the primitive to encrypt/decrypt files

    // Read the encrypted keyset
    KeysetHandle handle = null;
    try {
      handle = KeysetHandle.read(JsonKeysetReader.withFile(keyFile), kekAead);
    } catch (GeneralSecurityException | IOException ex) {
      System.err.println("Error reading key: " + ex);
      System.exit(1);
    }

    // Get the primitive
    Aead aead = null;
    try {
      aead = handle.getPrimitive(Aead.class);
    } catch (GeneralSecurityException ex) {
      System.err.println("Error creating primitive: %s " + ex);
      System.exit(1);
    }

    byte[] input = Files.readAllBytes(Paths.get(args[4]));
    File outputFile = new File(args[5]);

    if (MODE_ENCRYPT.equals(mode)) {
      byte[] ciphertext = aead.encrypt(input, EMPTY_ASSOCIATED_DATA);
      try (FileOutputStream stream = new FileOutputStream(outputFile)) {
        stream.write(ciphertext);
      }
    } else if (MODE_DECRYPT.equals(mode)) {
      byte[] plaintext = aead.decrypt(input, EMPTY_ASSOCIATED_DATA);
      try (FileOutputStream stream = new FileOutputStream(outputFile)) {
        stream.write(plaintext);
      }
    }

    System.exit(0);
  }

  private EncryptedKeysetExample() {}
}
// [END encrypted-keyset-example]
