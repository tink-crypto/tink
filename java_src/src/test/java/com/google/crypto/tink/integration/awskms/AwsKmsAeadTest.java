// Copyright 2017 Google Inc.
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
import static java.util.Arrays.asList;
import static org.junit.Assert.assertThrows;

import com.amazonaws.services.kms.AWSKMS;
import com.google.crypto.tink.Aead;
import com.google.crypto.tink.aead.AeadConfig;
import com.google.crypto.tink.subtle.Random;
import java.security.GeneralSecurityException;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Tests for AwsKmsAead. */
@RunWith(JUnit4.class)
public class AwsKmsAeadTest {
  private static final String KEY_ARN =
      "arn:aws:kms:us-west-2:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab";
  private static final String KEY_ARN_DIFFERENT = "arn:aws:kms:us-west-2:123:key/different";

  @BeforeClass
  public static void setUpClass() throws Exception {
    AeadConfig.register();
  }

  @Test
  public void testEncryptDecryptWithKnownKeyArn_success() throws Exception {
    AWSKMS kms = new FakeAwsKms(asList(KEY_ARN, KEY_ARN_DIFFERENT));

    Aead aead = new AwsKmsAead(kms, KEY_ARN);
    byte[] aad = Random.randBytes(20);
    byte[] message = Random.randBytes(42);
    byte[] ciphertext = aead.encrypt(message, aad);
    byte[] decrypted = aead.decrypt(ciphertext, aad);
    assertThat(decrypted).isEqualTo(message);
  }

  @Test
  public void testEncryptWithUnknownKeyArn_fails() throws Exception {
    AWSKMS kmsThatDoentKnowKeyArn = new FakeAwsKms(asList(KEY_ARN_DIFFERENT));

    Aead aead = new AwsKmsAead(kmsThatDoentKnowKeyArn, KEY_ARN);
    byte[] aad = Random.randBytes(20);
    byte[] message = Random.randBytes(20);
    assertThrows(GeneralSecurityException.class, () -> aead.encrypt(message, aad));
  }

  @Test
  public void testDecryptWithInvalidKeyArn_fails() throws Exception {
    AWSKMS kms = new FakeAwsKms(asList(KEY_ARN));
    Aead aead = new AwsKmsAead(kms, KEY_ARN);
    byte[] aad = Random.randBytes(20);
    byte[] invalidCiphertext = Random.randBytes(2);
    assertThrows(GeneralSecurityException.class, () -> aead.decrypt(invalidCiphertext, aad));
  }

  @Test
  public void testDecryptWithDifferentKeyArn_fails() throws Exception {
    AWSKMS kms = new FakeAwsKms(asList(KEY_ARN, KEY_ARN_DIFFERENT));

    Aead aead = new AwsKmsAead(kms, KEY_ARN);
    byte[] aad = Random.randBytes(20);
    byte[] message = Random.randBytes(20);

    // Create a valid ciphertext with a different ARN
    Aead aeadWithDifferentArn = new AwsKmsAead(kms, KEY_ARN_DIFFERENT);
    byte[] ciphertextFromDifferentArn = aeadWithDifferentArn.encrypt(message, aad);

    assertThrows(
        GeneralSecurityException.class, () -> aead.decrypt(ciphertextFromDifferentArn, aad));
  }

  @Test
  public void testDecryptWithAliasKeyArn_success() throws Exception {
    AWSKMS kms = new FakeAwsKms(asList(KEY_ARN));

    byte[] aad = Random.randBytes(20);
    byte[] message = Random.randBytes(20);

    // Create ciphertext for KEY_ARN
    Aead aead = new AwsKmsAead(kms, KEY_ARN);
    byte[] ciphertext = aead.encrypt(message, aad);

    // Use an alias ARN
    String aliasArn = "arn:aws:kms:us-west-2:111122223333:alias/ExampleAlias";
    Aead aeadWithAliasArn = new AwsKmsAead(kms, aliasArn);
    assertThat(aeadWithAliasArn.decrypt(ciphertext, aad)).isEqualTo(message);
  }

  @Test
  public void testDecryptWithInvalidKeyArn_success() throws Exception {
    AWSKMS kms = new FakeAwsKms(asList(KEY_ARN));

    byte[] aad = Random.randBytes(20);
    byte[] message = Random.randBytes(20);

    // Create ciphertext for KEY_ARN
    Aead aead = new AwsKmsAead(kms, KEY_ARN);
    byte[] ciphertext = aead.encrypt(message, aad);

    // Use an invalid Key ARN
    // TODO(b/242149560): Make this test case fail
    String invalidArn = "@#$@#$@#";
    Aead aeadWithInvalidArn = new AwsKmsAead(kms, invalidArn);
    assertThat(aeadWithInvalidArn.decrypt(ciphertext, aad)).isEqualTo(message);
  }
}
