/*
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
// [START gcs-envelope-aead-example]
package gcs;

import static java.nio.charset.StandardCharsets.UTF_8;

import com.google.auth.oauth2.GoogleCredentials;
import com.google.cloud.storage.BlobId;
import com.google.cloud.storage.BlobInfo;
import com.google.cloud.storage.Storage;
import com.google.cloud.storage.StorageOptions;
import com.google.crypto.tink.Aead;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.Registry;
import com.google.crypto.tink.aead.AeadConfig;
import com.google.crypto.tink.aead.KmsEnvelopeAeadKeyManager;
import com.google.crypto.tink.integration.gcpkms.GcpKmsClient;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.GeneralSecurityException;
import java.util.Arrays;
import java.util.Optional;

/**
 * A command-line utility for encrypting small files with envelope encryption and uploading the
 * results to GCS.
 *
 * <p>The CLI takes the following required arguments:
 *
 * <ul>
 *   <li>mode: "encrypt" or "decrypt" to indicate if you want to encrypt or decrypt.
 *   <li>kek-uri: The URI for the Cloud KMS key to be used for envelope encryption.
 *   <li>gcp-credential-file: Name of the file with the GCP credentials (in JSON format) that can
 *       access the Cloud KMS key and the GCS input/output blobs.
 *   <li>gcp-project-id: The ID of the GCP project hosting the GCS blobs that you want to encrypt or
 *       decrypt.
 * </ul>
 *
 * <p>When mode is "encrypt", it takes the following additional arguments:
 *
 * <ul>
 *   <li>local-input-file: Read the plaintext from this local file.
 *   <li>gcs-output-blob: Write the encryption result to this blob in GCS. The encryption result is
 *       bound to the location of this blob. That is, if you rename or move it to a different
 *       bucket, decryption will fail.
 * </ul>
 *
 * <p>When mode is "decrypt", it takes the following additional arguments:
 *
 * <ul>
 *   <li>gcs-input-blob: Read the ciphertext from this blob in GCS.
 *   <li>local-output-file: Write the decryption result to this local file.
 */
public final class GcsEnvelopeAeadExample {
  private static final String MODE_ENCRYPT = "encrypt";
  private static final String MODE_DECRYPT = "decrypt";
  private static final String GCS_PATH_PREFIX = "gs://";

  public static void main(String[] args) throws Exception {
    if (args.length != 6) {
      System.err.printf("Expected 6 parameters, got %d\n", args.length);
      System.err.println(
          "Usage: java GcsEnvelopeAeadExample encrypt/decrypt kek-uri gcp-credential-file"
              + " gcp-project-id input-file output-file");
      System.exit(1);
    }
    String mode = args[0];
    String kekUri = args[1];
    String gcpCredentialFilename = args[2];
    String gcpProjectId = args[3];

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
                  kekUri, Registry.keyTemplates().get("AES256_GCM")));
      aead = handle.getPrimitive(Aead.class);
    } catch (GeneralSecurityException ex) {
      System.err.println("Error creating primitive: %s " + ex);
      System.exit(1);
    }

    GoogleCredentials credentials =
        GoogleCredentials.fromStream(new FileInputStream(gcpCredentialFilename))
            .createScoped(Arrays.asList("https://www.googleapis.com/auth/cloud-platform"));
    Storage storage =
        StorageOptions.newBuilder()
            .setProjectId(gcpProjectId)
            .setCredentials(credentials)
            .build()
            .getService();

    // Use the primitive to encrypt/decrypt files.
    if (MODE_ENCRYPT.equals(mode)) {
      // Encrypt the local file
      byte[] input = Files.readAllBytes(Paths.get(args[4]));
      String gcsBlobPath = args[5];
      // This will bind the encryption to the location of the GCS blob. That if, if you rename or
      // move the blob to a different bucket, decryption will fail.
      // See https://developers.google.com/tink/AEAD#associated_data.
      byte[] associatedData = gcsBlobPath.getBytes(UTF_8);
      byte[] ciphertext = aead.encrypt(input, associatedData);

      // Upload to GCS
      String bucketName = getBucketName(gcsBlobPath);
      String objectName = getObjectName(gcsBlobPath);
      BlobId blobId = BlobId.of(bucketName, objectName);
      BlobInfo blobInfo = BlobInfo.newBuilder(blobId).build();
      storage.create(blobInfo, ciphertext);
    } else if (MODE_DECRYPT.equals(mode)) {
      // Download the GCS blob
      String gcsBlobPath = args[4];
      String bucketName = getBucketName(gcsBlobPath);
      String objectName = getObjectName(gcsBlobPath);
      byte[] input = storage.readAllBytes(bucketName, objectName);

      // Decrypt to a local file
      byte[] associatedData = gcsBlobPath.getBytes(UTF_8);
      byte[] plaintext = aead.decrypt(input, associatedData);
      File outputFile = new File(args[5]);
      try (FileOutputStream stream = new FileOutputStream(outputFile)) {
        stream.write(plaintext);
      }
    } else {
      System.err.println("The first argument must be either encrypt or decrypt, got: " + mode);
      System.exit(1);
    }

    System.exit(0);
  }

  private static String getBucketName(String gcsBlobPath) {
    if (!gcsBlobPath.startsWith(GCS_PATH_PREFIX)) {
      throw new IllegalArgumentException(
          "GCS blob paths must start with gs://, got " + gcsBlobPath);
    }

    String bucketAndObjectName = gcsBlobPath.substring(GCS_PATH_PREFIX.length());
    int firstSlash = bucketAndObjectName.indexOf("/");
    if (firstSlash == -1) {
      throw new IllegalArgumentException(
          "GCS blob paths must have format gs://my-bucket-name/my-object-name, got " + gcsBlobPath);
    }
    return bucketAndObjectName.substring(0, firstSlash);
  }

  private static String getObjectName(String gcsBlobPath) {
    if (!gcsBlobPath.startsWith(GCS_PATH_PREFIX)) {
      throw new IllegalArgumentException(
          "GCS blob paths must start with gs://, got " + gcsBlobPath);
    }

    String bucketAndObjectName = gcsBlobPath.substring(GCS_PATH_PREFIX.length());
    int firstSlash = bucketAndObjectName.indexOf("/");
    if (firstSlash == -1) {
      throw new IllegalArgumentException(
          "GCS blob paths must have format gs://my-bucket-name/my-object-name, got " + gcsBlobPath);
    }
    return bucketAndObjectName.substring(firstSlash + 1);
  }

  private GcsEnvelopeAeadExample() {}
}
// [END gcs-envelope-aead-example]
