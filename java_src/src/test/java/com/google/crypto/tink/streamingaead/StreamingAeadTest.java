// Copyright 2022 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
////////////////////////////////////////////////////////////////////////////////

package com.google.crypto.tink.streamingaead;

import static com.google.common.truth.Truth.assertThat;
import static java.nio.charset.StandardCharsets.UTF_8;
import static org.junit.Assert.assertThrows;

import com.google.crypto.tink.DeterministicAead;
import com.google.crypto.tink.InsecureSecretKeyAccess;
import com.google.crypto.tink.KeyTemplates;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.StreamingAead;
import com.google.crypto.tink.TinkJsonProtoKeysetFormat;
import com.google.crypto.tink.daead.DeterministicAeadConfig;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.Channels;
import java.nio.channels.ReadableByteChannel;
import java.nio.channels.WritableByteChannel;
import java.security.GeneralSecurityException;
import org.junit.BeforeClass;
import org.junit.experimental.theories.DataPoints;
import org.junit.experimental.theories.FromDataPoints;
import org.junit.experimental.theories.Theories;
import org.junit.experimental.theories.Theory;
import org.junit.runner.RunWith;

/** Unit tests for the StreamingAead package. Uses only the public API. */
@RunWith(Theories.class)
public final class StreamingAeadTest {

  @BeforeClass
  public static void setUp() throws Exception {
    StreamingAeadConfig.register();
    DeterministicAeadConfig.register(); // Needed for getPrimitiveFromNonStreamingAeadKeyset_throws.
  }

  @DataPoints("templates")
  public static final String[] TEMPLATES =
      new String[] {
        "AES128_GCM_HKDF_4KB",
        "AES128_GCM_HKDF_1MB",
        "AES256_GCM_HKDF_4KB",
        "AES256_GCM_HKDF_1MB",
        "AES128_CTR_HMAC_SHA256_4KB",
        "AES128_CTR_HMAC_SHA256_1MB",
        "AES256_CTR_HMAC_SHA256_4KB",
        "AES256_CTR_HMAC_SHA256_1MB"
      };

  /** Writes {@code data} to {@code writeableChannel}. */
  private void writeToChannel(WritableByteChannel writeableChannel, byte[] data)
      throws IOException {
    ByteBuffer buffer = ByteBuffer.wrap(data);
    int bytesWritten = 0;
    while (bytesWritten < data.length) {
      bytesWritten += writeableChannel.write(buffer);
    }
  }

  /** Reads {@code bytesToRead} bytes from {@code readableChannel}.*/
  private byte[] readFromChannel(ReadableByteChannel readableChannel, int bytesToRead)
      throws IOException {
    ByteBuffer buffer = ByteBuffer.allocate(bytesToRead);
    int bytesRead = 0;
    while (bytesRead < bytesToRead) {
      bytesRead += readableChannel.read(buffer);
    }
    return buffer.array();
  }

  @Theory
  public void createEncryptDecrypt(@FromDataPoints("templates") String templateName)
      throws Exception {
    KeysetHandle handle = KeysetHandle.generateNew(KeyTemplates.get(templateName));
    StreamingAead streamingAead = handle.getPrimitive(StreamingAead.class);

    byte[] plaintext = "plaintext".getBytes(UTF_8);
    byte[] associatedData = "associatedData".getBytes(UTF_8);

    // Encrypt
    ByteArrayOutputStream ciphertextOutputStream = new ByteArrayOutputStream();
    try (WritableByteChannel encryptingChannel =
        streamingAead.newEncryptingChannel(
            Channels.newChannel(ciphertextOutputStream), associatedData)) {
      writeToChannel(encryptingChannel, plaintext);
    }
    byte[] ciphertext = ciphertextOutputStream.toByteArray();

    // Decrypt
    byte[] decrypted = null;
    ReadableByteChannel ciphertextSource =
        Channels.newChannel(new ByteArrayInputStream(ciphertext));
    try (ReadableByteChannel decryptingChannel =
        streamingAead.newDecryptingChannel(ciphertextSource, associatedData)) {
      decrypted = readFromChannel(decryptingChannel, plaintext.length);
    }
    assertThat(decrypted).isEqualTo(plaintext);

    // Decrypt with invalid associatedData fails
    byte[] invalidAssociatedData = "invalid".getBytes(UTF_8);
    ByteBuffer decrypted2 = ByteBuffer.allocate(plaintext.length);
    ReadableByteChannel ciphertextSource2 =
        Channels.newChannel(new ByteArrayInputStream(ciphertext));
    try (ReadableByteChannel decryptingChannel =
        streamingAead.newDecryptingChannel(ciphertextSource2, invalidAssociatedData)) {
      assertThrows(IOException.class, () -> decryptingChannel.read(decrypted2));
    }
  }

  // A keyset with one StreamingAead key, serialized in Tink's JSON format.
  private static final String JSON_STREAMING_AEAD_KEYSET =
      ""
      + "{"
      + "  \"primaryKeyId\": 1261393457,"
      + "  \"key\": ["
      + "    {"
      + "      \"keyData\": {"
      + "        \"typeUrl\":"
      + "\"type.googleapis.com/google.crypto.tink.AesCtrHmacStreamingKey\","
      + "        \"value\": \"GhBqEXuGvNvVCRjJX1IMvC0kEg4iBBAgCAMYAxAQCICAQA==\","
      + "        \"keyMaterialType\": \"SYMMETRIC\""
      + "      },"
      + "      \"status\": \"ENABLED\","
      + "      \"keyId\": 1261393457,"
      + "      \"outputPrefixType\": \"RAW\""
      + "    }"
      + "  ]"
      + "}";

  @Theory
  public void readKeyset_encryptDecrypt_success() throws Exception {
    KeysetHandle handle =
        TinkJsonProtoKeysetFormat.parseKeyset(
            JSON_STREAMING_AEAD_KEYSET, InsecureSecretKeyAccess.get());
    StreamingAead streamingAead = handle.getPrimitive(StreamingAead.class);

    byte[] plaintext = "plaintext".getBytes(UTF_8);
    byte[] associatedData = "associatedData".getBytes(UTF_8);

    ByteArrayOutputStream ciphertextOutputStream = new ByteArrayOutputStream();
    try (WritableByteChannel encryptingChannel =
        streamingAead.newEncryptingChannel(
            Channels.newChannel(ciphertextOutputStream), associatedData)) {
      writeToChannel(encryptingChannel, plaintext);
    }
    byte[] ciphertext = ciphertextOutputStream.toByteArray();

    byte[] decrypted = null;
    ReadableByteChannel ciphertextSource =
        Channels.newChannel(new ByteArrayInputStream(ciphertext));
    try (ReadableByteChannel decryptingChannel =
        streamingAead.newDecryptingChannel(ciphertextSource, associatedData)) {
      decrypted = readFromChannel(decryptingChannel, plaintext.length);
    }
    assertThat(decrypted).isEqualTo(plaintext);
  }

  // A keyset with multiple keys. The first key is the same as in JSON_STREAMING_AEAD_KEYSET.
  private static final String JSON_STREAMING_AEAD_KEYSET_WITH_MULTIPLE_KEYS =
      ""
          + "{"
          + "  \"primaryKeyId\": 1539463392,"
          + "  \"key\": ["
          + "    {"
          + "      \"keyData\": {"
          + "        \"typeUrl\":"
          + "\"type.googleapis.com/google.crypto.tink.AesCtrHmacStreamingKey\","
          + "        \"value\": \"GhBqEXuGvNvVCRjJX1IMvC0kEg4iBBAgCAMYAxAQCICAQA==\","
          + "        \"keyMaterialType\": \"SYMMETRIC\""
          + "      },"
          + "      \"status\": \"ENABLED\","
          + "      \"keyId\": 1261393457,"
          + "      \"outputPrefixType\": \"RAW\""
          + "    },"
          + "    {"
          + "      \"keyData\": {"
          + "        \"typeUrl\":"
          + "\"type.googleapis.com/google.crypto.tink.AesCtrHmacStreamingKey\","
          + "        \"value\":"
          + "\"GiA33jWXeuaAVvmFGQdU71KKA1K0rUQV8moj5LupxpgCJRIOIgQQIAgDGAMQIAiAgEA=\","
          + "        \"keyMaterialType\": \"SYMMETRIC\""
          + "      },"
          + "      \"status\": \"ENABLED\","
          + "      \"keyId\": 1539463392,"
          + "      \"outputPrefixType\": \"RAW\""
          + "    },"
          + "    {"
          + "      \"keyData\": {"
          + "        \"typeUrl\":"
          + "\"type.googleapis.com/google.crypto.tink.AesCtrHmacStreamingKey\","
          + "        \"value\":"
          + "\"GiBpie88LEnKNiGNtyDiUwDmDzeHgrpmf4k2tC1OaWUpcRIOIgQQIAgDGAMQIAiAgEA=\","
          + "        \"keyMaterialType\": \"SYMMETRIC\""
          + "      },"
          + "      \"status\": \"ENABLED\","
          + "      \"keyId\": 552736913,"
          + "      \"outputPrefixType\": \"RAW\""
          + "    }"
          + "  ]"
          + "}";

  @Theory
  public void multipleKeysReadKeyset_encryptDecrypt_success() throws Exception {
    KeysetHandle handle =
        TinkJsonProtoKeysetFormat.parseKeyset(
            JSON_STREAMING_AEAD_KEYSET_WITH_MULTIPLE_KEYS, InsecureSecretKeyAccess.get());
    StreamingAead streamingAead = handle.getPrimitive(StreamingAead.class);

    byte[] plaintext = "plaintext".getBytes(UTF_8);
    byte[] associatedData = "associatedData".getBytes(UTF_8);

    ByteArrayOutputStream ciphertextOutputStream = new ByteArrayOutputStream();
    try (WritableByteChannel encryptingChannel =
        streamingAead.newEncryptingChannel(
            Channels.newChannel(ciphertextOutputStream), associatedData)) {
      writeToChannel(encryptingChannel, plaintext);
    }
    byte[] ciphertext = ciphertextOutputStream.toByteArray();

    byte[] decrypted = null;
    ReadableByteChannel ciphertextSource =
        Channels.newChannel(new ByteArrayInputStream(ciphertext));
    try (ReadableByteChannel decryptingChannel =
        streamingAead.newDecryptingChannel(ciphertextSource, associatedData)) {
      decrypted = readFromChannel(decryptingChannel, plaintext.length);
    }
    assertThat(decrypted).isEqualTo(plaintext);
  }

  // A keyset with a valid DeterministicAead key. This keyset can't be used with the StreamingAead
  // primitive.
  private static final String JSON_DAEAD_KEYSET =
      ""
          + "{"
          + "  \"primaryKeyId\": 961932622,"
          + "  \"key\": ["
          + "    {"
          + "      \"keyData\": {"
          + "        \"typeUrl\": \"type.googleapis.com/google.crypto.tink.AesSivKey\","
          + "        \"keyMaterialType\": \"SYMMETRIC\","
          + "        \"value\": \"EkCJ9r5iwc5uxq5ugFyrHXh5dijTa7qalWUgZ8Gf08RxNd545FjtLMYL7ObcaFtCS"
          + "kvV2+7u6F2DN+kqUjAfkf2W\""
          + "      },"
          + "      \"outputPrefixType\": \"TINK\","
          + "      \"keyId\": 961932622,"
          + "      \"status\": \"ENABLED\""
          + "    }"
          + "  ]"
          + "}";

  @Theory
  public void getPrimitiveFromNonStreamingAeadKeyset_throws()
      throws Exception {
    KeysetHandle handle =
        TinkJsonProtoKeysetFormat.parseKeyset(
            JSON_DAEAD_KEYSET, InsecureSecretKeyAccess.get());
    // Test that the keyset can create a DeterministicAead primitive, but not a StreamingAead.
    handle.getPrimitive(DeterministicAead.class);
    assertThrows(GeneralSecurityException.class, () -> handle.getPrimitive(StreamingAead.class));
  }
}
