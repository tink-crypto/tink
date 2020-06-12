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

package com.google.crypto.tink.daead;

import static com.google.common.truth.Truth.assertThat;
import static org.junit.Assert.fail;

import com.google.crypto.tink.DeterministicAead;
import com.google.crypto.tink.KeyTemplate;
import com.google.crypto.tink.KeyTypeManager;
import com.google.crypto.tink.proto.AesSivKey;
import com.google.crypto.tink.proto.AesSivKeyFormat;
import com.google.crypto.tink.proto.KeyData.KeyMaterialType;
import com.google.crypto.tink.subtle.Random;
import com.google.crypto.tink.testing.TestUtil;
import com.google.protobuf.ByteString;
import com.google.protobuf.ExtensionRegistryLite;
import java.security.GeneralSecurityException;
import java.util.TreeSet;
import javax.crypto.Cipher;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Test for AesSivKeyManager. */
@RunWith(JUnit4.class)
public class AesSivKeyManagerTest {
  @Test
  public void basics() throws Exception {
    assertThat(new AesSivKeyManager().getKeyType())
        .isEqualTo("type.googleapis.com/google.crypto.tink.AesSivKey");
    assertThat(new AesSivKeyManager().getVersion()).isEqualTo(0);
    assertThat(new AesSivKeyManager().keyMaterialType()).isEqualTo(KeyMaterialType.SYMMETRIC);
  }

  @Test
  public void validateKeyFormat_empty() throws Exception {
    try {
      new AesSivKeyManager().keyFactory().validateKeyFormat(AesSivKeyFormat.getDefaultInstance());
      fail();
    } catch (GeneralSecurityException e) {
      // expected
    }
  }

  @Test
  public void validateKeyFormat_checkAllLengths() throws Exception {
    AesSivKeyManager manager = new AesSivKeyManager();
    for (int i = 0; i < 100; i++) {
      if (i == 64) {
        manager.keyFactory().validateKeyFormat(createAesSivKeyFormat(i));
      } else {
        try {
          manager.keyFactory().validateKeyFormat(createAesSivKeyFormat(i));
          fail();
        } catch (GeneralSecurityException e) {
          // expected
        }
      }
    }
  }

  @Test
  public void validateKey_empty() throws Exception {
    try {
      new AesSivKeyManager().validateKey(AesSivKey.getDefaultInstance());
      fail();
    } catch (GeneralSecurityException e) {
      // expected
    }
  }

  @Test
  public void validateKey_checkAllLengths() throws Exception {
    AesSivKeyManager manager = new AesSivKeyManager();
    for (int i = 0; i < 100; i++) {
      if (i == 64) {
        manager.validateKey(createAesSivKey(i));
      } else {
        try {
          manager.validateKey(createAesSivKey(i));
          fail();
        } catch (GeneralSecurityException e) {
          // expected
        }
      }
    }
  }

  @Test
  public void validateKey_version() throws Exception {
    AesSivKeyManager manager = new AesSivKeyManager();
    try {
      manager.validateKey(AesSivKey.newBuilder(createAesSivKey(64)).setVersion(1).build());
      fail();
    } catch (GeneralSecurityException e) {
      // expected
    }
  }

  @Test
  public void createKey_valid() throws Exception {
    AesSivKeyFormat format = createAesSivKeyFormat(64);
    AesSivKey key = new AesSivKeyManager().keyFactory().createKey(format);
    new AesSivKeyManager().validateKey(key);
  }

  @Test
  public void createKey_values() throws Exception {
    AesSivKeyFormat format = createAesSivKeyFormat(64);
    AesSivKey key = new AesSivKeyManager().keyFactory().createKey(format);
    assertThat(key.getVersion()).isEqualTo(0);
    assertThat(key.getKeyValue()).hasSize(format.getKeySize());
  }

  @Test
  public void createKey_multipleCallsCreateDifferentKeys() throws Exception {
    AesSivKeyFormat format = createAesSivKeyFormat(64);
    TreeSet<String> keys = new TreeSet<>();
    KeyTypeManager.KeyFactory<AesSivKeyFormat, AesSivKey> factory =
        new AesSivKeyManager().keyFactory();
    final int numKeys = 1000;
    for (int i = 0; i < numKeys; ++i) {
      keys.add(TestUtil.hexEncode(factory.createKey(format).toByteArray()));
    }
    assertThat(keys).hasSize(numKeys);
  }

  @Test
  public void testCiphertextSize() throws Exception {
    if (Cipher.getMaxAllowedKeyLength("AES") < 256) {
      System.out.println(
          "Unlimited Strength Jurisdiction Policy Files are required"
              + " but not installed. Skipping testCiphertextSize");
      return;
    }

    DeterministicAead daead =
        new AesSivKeyManager().getPrimitive(createAesSivKey(64), DeterministicAead.class);
    byte[] plaintext = "plaintext".getBytes("UTF-8");
    byte[] associatedData = "associatedData".getBytes("UTF-8");
    assertThat(daead.encryptDeterministically(plaintext, associatedData))
        .hasLength(plaintext.length + /* IV_SIZE= */ 16);
  }

  private AesSivKeyFormat createAesSivKeyFormat(int keySize) {
    return AesSivKeyFormat.newBuilder().setKeySize(keySize).build();
  }

  private AesSivKey createAesSivKey(int keySize) {
    return AesSivKey.newBuilder()
        .setKeyValue(ByteString.copyFrom(Random.randBytes(keySize)))
        .build();
  }

  @Test
  public void testAes256SivTemplate() throws Exception {
    KeyTemplate template = AesSivKeyManager.aes256SivTemplate();
    assertThat(template.getTypeUrl()).isEqualTo(new AesSivKeyManager().getKeyType());
    assertThat(template.getOutputPrefixType()).isEqualTo(KeyTemplate.OutputPrefixType.TINK);
    AesSivKeyFormat format =
        AesSivKeyFormat.parseFrom(template.getValue(), ExtensionRegistryLite.getEmptyRegistry());

    assertThat(format.getKeySize()).isEqualTo(format.getKeySize());
  }

  @Test
  public void testRawAes256SivTemplate() throws Exception {
    KeyTemplate template = AesSivKeyManager.rawAes256SivTemplate();
    assertThat(template.getTypeUrl()).isEqualTo(new AesSivKeyManager().getKeyType());
    assertThat(template.getOutputPrefixType()).isEqualTo(KeyTemplate.OutputPrefixType.RAW);
    AesSivKeyFormat format =
        AesSivKeyFormat.parseFrom(template.getValue(), ExtensionRegistryLite.getEmptyRegistry());

    assertThat(format.getKeySize()).isEqualTo(format.getKeySize());
  }
}
