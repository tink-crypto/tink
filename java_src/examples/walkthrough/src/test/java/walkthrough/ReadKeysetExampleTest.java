/*
 * Copyright 2023 Google LLC
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
package walkthrough;

import static com.google.common.truth.Truth.assertThat;
import static java.nio.charset.StandardCharsets.UTF_8;

import com.google.crypto.tink.Aead;
import com.google.crypto.tink.InsecureSecretKeyAccess;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.KmsClient;
import com.google.crypto.tink.TinkJsonProtoKeysetFormat;
import com.google.crypto.tink.aead.AeadConfig;
import com.google.crypto.tink.testing.FakeKmsClient;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

@RunWith(JUnit4.class)
public final class ReadKeysetExampleTest {
  private static final String KEYSET_TO_SERIALIZE =
      "{"
          + "  \"key\": ["
          + "    {"
          + "      \"keyData\": {"
          + "        \"keyMaterialType\": \"SYMMETRIC\","
          + "        \"typeUrl\": \"type.googleapis.com/google.crypto.tink.AesGcmKey\","
          + "        \"value\": \"GhD+9l0RANZjzZEZ8PDp7LRW\""
          + "      },"
          + "      \"keyId\": 1931667682,"
          + "      \"outputPrefixType\": \"TINK\","
          + "      \"status\": \"ENABLED\""
          + "    }"
          + "  ],"
          + "  \"primaryKeyId\": 1931667682"
          + "}";

  @Test
  public void readEncryptedKeyset_succeedsWithValidInputs() throws Exception {
    AeadConfig.register();

    KmsClient kmsClient = new FakeKmsClient();
    String keyEncryptionKeyUri = FakeKmsClient.createFakeKeyUri();
    Aead keyEncryptionAead = kmsClient.getAead(keyEncryptionKeyUri);

    byte[] plaintext = "plaintext".getBytes(UTF_8);
    byte[] associatedData = "associatedData".getBytes(UTF_8);
    byte[] keysetAssociatedData = "keysetAssociatedData".getBytes(UTF_8);

    KeysetHandle keysetHandle =
        TinkJsonProtoKeysetFormat.parseKeyset(KEYSET_TO_SERIALIZE, InsecureSecretKeyAccess.get());
    String serializedEncryptedKeyset =
        TinkJsonProtoKeysetFormat.serializeEncryptedKeyset(
            keysetHandle, keyEncryptionAead, keysetAssociatedData);

    KeysetHandle deserializedKeyset =
        ReadKeysetExample.readEncryptedKeyset(
            serializedEncryptedKeyset, keyEncryptionAead, keysetAssociatedData);
    // Make sure the keyset was read correctly trying to decrypt ciphertext.
    byte[] decrypted =
        ObtainAndUseAeadPrimitiveExample.aeadEncryptDecrypt(
            deserializedKeyset, plaintext, associatedData);
    assertThat(decrypted).isEqualTo(plaintext);
  }
}
