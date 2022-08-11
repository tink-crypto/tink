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
package com.google.crypto.tink.integration.awskms;

import static com.google.common.truth.Truth.assertThat;
import static java.nio.charset.StandardCharsets.UTF_8;
import static java.util.Arrays.asList;
import static org.junit.Assert.assertThrows;

import com.amazonaws.AmazonServiceException;
import com.amazonaws.services.kms.AWSKMS;
import com.amazonaws.services.kms.model.DecryptRequest;
import com.amazonaws.services.kms.model.DecryptResult;
import com.amazonaws.services.kms.model.EncryptRequest;
import com.amazonaws.services.kms.model.EncryptResult;
import com.google.crypto.tink.aead.AeadConfig;
import java.nio.ByteBuffer;
import java.util.HashMap;
import java.util.Map;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

@RunWith(JUnit4.class)
public final class FakeAwsKmsTest {

  private static final String KEY_ID =
      "arn:aws:kms:us-west-2:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab";
  private static final String KEY_ID_2 = "arn:aws:kms:us-west-2:123:key/different";

  @BeforeClass
  public static void setUpClass() throws Exception {
    AeadConfig.register();
  }

  @Test
  public void testEncryptDecryptWithValidKeyId_success() throws Exception {
    AWSKMS kms = new FakeAwsKms(asList(KEY_ID));

    byte[] plaintext = "plaintext".getBytes(UTF_8);

    Map<String, String> context = new HashMap<>();
    context.put("name", "value");

    EncryptRequest encRequest =
        new EncryptRequest()
            .withKeyId(KEY_ID)
            .withPlaintext(ByteBuffer.wrap(plaintext))
            .withEncryptionContext(context);
    EncryptResult encResult = kms.encrypt(encRequest);
    assertThat(encResult.getKeyId()).isEqualTo(KEY_ID);

    DecryptRequest decRequest =
        new DecryptRequest()
            .withCiphertextBlob(ByteBuffer.wrap(encResult.getCiphertextBlob().array()))
            .withEncryptionContext(context);

    DecryptResult decResult = kms.decrypt(decRequest);
    assertThat(decResult.getKeyId()).isEqualTo(KEY_ID);
    assertThat(decResult.getPlaintext().array()).isEqualTo(plaintext);
  }

  @Test
  public void testEncryptWithInvalidKeyId_fails() throws Exception {
    AWSKMS kms = new FakeAwsKms(asList(KEY_ID));

    byte[] plaintext = "plaintext".getBytes(UTF_8);

    Map<String, String> context = new HashMap<>();
    context.put("name", "value");

    EncryptRequest encRequestWithDifferentKeyArn =
        new EncryptRequest()
            .withKeyId(KEY_ID_2)
            .withPlaintext(ByteBuffer.wrap(plaintext))
            .withEncryptionContext(context);
    assertThrows(AmazonServiceException.class, () -> kms.encrypt(encRequestWithDifferentKeyArn));
  }

  @Test
  public void testDecryptWithInvalidKeyId_fails() throws Exception {
    AWSKMS kms = new FakeAwsKms(asList(KEY_ID));

    byte[] invalidCiphertext = "invalid".getBytes(UTF_8);

    Map<String, String> context = new HashMap<>();
    context.put("name", "value");

    DecryptRequest decRequestWithInvalidCiphertext =
        new DecryptRequest()
            .withCiphertextBlob(ByteBuffer.wrap(invalidCiphertext))
            .withEncryptionContext(context);
    assertThrows(AmazonServiceException.class, () -> kms.decrypt(decRequestWithInvalidCiphertext));
  }


  @Test
  public void testEncryptDecryptWithTwoValidKeyId_success() throws Exception {
    AWSKMS kms = new FakeAwsKms(asList(KEY_ID, KEY_ID_2));

    byte[] plaintext = "plaintext".getBytes(UTF_8);
    byte[] plaintext2 = "plaintext2".getBytes(UTF_8);

    Map<String, String> context = new HashMap<>();
    context.put("name", "value");

    EncryptRequest encRequest =
        new EncryptRequest()
            .withKeyId(KEY_ID)
            .withPlaintext(ByteBuffer.wrap(plaintext))
            .withEncryptionContext(context);
    EncryptResult encResult = kms.encrypt(encRequest);
    assertThat(encResult.getKeyId()).isEqualTo(KEY_ID);

    EncryptRequest encRequest2 =
        new EncryptRequest()
            .withKeyId(KEY_ID_2)
            .withPlaintext(ByteBuffer.wrap(plaintext2))
            .withEncryptionContext(context);
    EncryptResult encResult2 = kms.encrypt(encRequest2);
    assertThat(encResult2.getKeyId()).isEqualTo(KEY_ID_2);

    DecryptRequest decRequest =
        new DecryptRequest()
            .withCiphertextBlob(ByteBuffer.wrap(encResult.getCiphertextBlob().array()))
            .withEncryptionContext(context);

    DecryptResult decResult = kms.decrypt(decRequest);
    assertThat(decResult.getKeyId()).isEqualTo(KEY_ID);
    assertThat(decResult.getPlaintext().array()).isEqualTo(plaintext);

    DecryptRequest decRequest2 =
        new DecryptRequest()
            .withCiphertextBlob(ByteBuffer.wrap(encResult2.getCiphertextBlob().array()))
            .withEncryptionContext(context);

    DecryptResult decResult2 = kms.decrypt(decRequest2);
    assertThat(decResult2.getKeyId()).isEqualTo(KEY_ID_2);
    assertThat(decResult2.getPlaintext().array()).isEqualTo(plaintext2);
  }

}
