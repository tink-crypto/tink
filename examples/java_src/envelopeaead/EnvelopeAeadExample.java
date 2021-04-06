/*
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
// [START envelope-example]
package envelopeaead;

import static java.nio.charset.StandardCharsets.UTF_8;

import com.google.crypto.tink.Aead;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.aead.AeadConfig;
import com.google.crypto.tink.aead.AesGcmKeyManager;
import com.google.crypto.tink.aead.KmsEnvelopeAeadKeyManager;
import com.google.crypto.tink.integration.gcpkms.GcpKmsClient;
import java.io.File;
import java.io.FileOutputStream;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.GeneralSecurityException;
import java.util.Optional;

/**
 * A command-line utility for encrypting small files with AEAD.
 *
 * <p>It loads cleartext keys from disk - this is not recommended!
 *
 * <p>It requires the following arguments:
 *
 * <ul>
 *   <li>mode: Can be "encrypt" or "decrypt" to encrypt/decrypt the input to the output.
 *   <li>kek-uri: Use this Cloud KMS' key as the key-encrypting-key for envelope encryption.
 *   <li>gcp-credential-file: Use this JSON credential file to connect to Cloud KMS.
 *   <li>input-file: Read the input from this file.
 *   <li>output-file: Write the result to this file.
 *   <li>[optional] associated-data: Associated data used for the encryption or decryption.
 */
public final class EnvelopeAeadExample {
  private static final String MODE_ENCRYPT = "encrypt";
  private static final String MODE_DECRYPT = "decrypt";

  public static void main(String[] args) throws Exception {
    if (args.length != 5 && args.length != 6) {
      System.err.printf("Expected 5 or 6 parameters, got %d\n", args.length);
      System.err.println(
          "Usage: java EnvelopeAeadExample encrypt/decrypt kek-uri gcp-credential-file"
              + " input-file output-file [associated-data]");
      System.exit(1);
    }
    String mode = args[0];
    String kekUri = args[1];
    String gcpCredentialFilename = args[2];
    byte[] input = Files.readAllBytes(Paths.get(args[3]));
    File outputFile = new File(args[4]);
    byte[] associatedData = new byte[0];
    if (args.length == 6) {
      System.out.println("Associated data!");
      associatedData = args[5].getBytes(UTF_8);
    }
    // Initialise Tink: register all AEAD key types with the Tink runtime
    AeadConfig.register();

    // Read the GCP credentials and set up client
    try {
      GcpKmsClient.register(Optional.of(kekUri), Optional.of(gcpCredentialFilename));
    } catch (GeneralSecurityException ex) {
      System.err.println("Error initializing GCP client: " + ex);
      System.exit(1);
    }

    // Create envelope AEAD primitive using AES256 GCM for encrypting the data
    Aead aead = null;
    try {
      KeysetHandle handle =
          KeysetHandle.generateNew(
              KmsEnvelopeAeadKeyManager.createKeyTemplate(
                  kekUri, AesGcmKeyManager.aes128GcmTemplate()));
      aead = handle.getPrimitive(Aead.class);
    } catch (GeneralSecurityException ex) {
      System.err.println("Error creating primitive: %s " + ex);
      System.exit(1);
    }

    // Use the primitive to encrypt/decrypt files.
    if (MODE_ENCRYPT.equals(mode)) {
      byte[] ciphertext = aead.encrypt(input, associatedData);
      try (FileOutputStream stream = new FileOutputStream(outputFile)) {
        stream.write(ciphertext);
      }
    } else if (MODE_DECRYPT.equals(mode)) {
      byte[] plaintext = aead.decrypt(input, associatedData);
      try (FileOutputStream stream = new FileOutputStream(outputFile)) {
        stream.write(plaintext);
      }
    } else {
      System.err.println("The first argument must be either encrypt or decrypt, got: " + mode);
      System.exit(1);
    }

    System.exit(0);
  }

  private EnvelopeAeadExample() {}
}
// [END envelope-example]
