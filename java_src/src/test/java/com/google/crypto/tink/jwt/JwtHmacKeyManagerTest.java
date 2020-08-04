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

package com.google.crypto.tink.jwt;

import static com.google.common.truth.Truth.assertThat;
import static com.google.crypto.tink.testing.KeyTypeManagerTestUtil.testKeyTemplateCompatible;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.fail;

import com.google.crypto.tink.KeyTemplate;
import com.google.crypto.tink.KeyTypeManager;
import com.google.crypto.tink.proto.HashType;
import com.google.crypto.tink.proto.JwtHmacKey;
import com.google.crypto.tink.proto.JwtHmacKeyFormat;
import com.google.crypto.tink.subtle.Random;
import com.google.crypto.tink.testing.TestUtil;
import com.google.protobuf.ByteString;
import com.google.protobuf.ExtensionRegistryLite;
import java.io.ByteArrayInputStream;
import java.security.GeneralSecurityException;
import java.util.Set;
import java.util.TreeSet;
import javax.crypto.spec.SecretKeySpec;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Unit tests for {@link JwtHmacKeyManager}. */
@RunWith(JUnit4.class)
public class JwtHmacKeyManagerTest {
  private final JwtHmacKeyManager manager = new JwtHmacKeyManager();
  private final KeyTypeManager.KeyFactory<JwtHmacKeyFormat, JwtHmacKey> factory =
      manager.keyFactory();

  @Test
  public void validateKeyFormat_empty() throws Exception {
    try {
      factory.validateKeyFormat(JwtHmacKeyFormat.getDefaultInstance());
      fail("At least the hash type needs to be set");
    } catch (GeneralSecurityException e) {
      // expected.
    }
  }

  private static JwtHmacKeyFormat makeJwtHmacKeyFormat(int keySize, HashType hashType) {
    return JwtHmacKeyFormat.newBuilder().setHashType(hashType).setKeySize(keySize).build();
  }

  @Test
  public void validateKeyFormat_sha256() throws Exception {
    factory.validateKeyFormat(makeJwtHmacKeyFormat(32, HashType.SHA256));
  }

  @Test
  public void validateKeyFormat_sha512() throws Exception {
    factory.validateKeyFormat(makeJwtHmacKeyFormat(32, HashType.SHA512));
  }

  @Test
  public void validateKeyFormat_keySizes() throws Exception {
    try {
      factory.validateKeyFormat(makeJwtHmacKeyFormat(31, HashType.SHA256));
      fail();
    } catch (GeneralSecurityException e) {
      // expected
    }
  }

  @Test
  public void createKey_valid() throws Exception {
    manager.validateKey(factory.createKey(makeJwtHmacKeyFormat(32, HashType.SHA256)));
    manager.validateKey(factory.createKey(makeJwtHmacKeyFormat(32, HashType.SHA256)));
    manager.validateKey(factory.createKey(makeJwtHmacKeyFormat(32, HashType.SHA512)));
  }

  @Test
  public void createKey_checkValues() throws Exception {
    JwtHmacKeyFormat keyFormat = makeJwtHmacKeyFormat(32, HashType.SHA256);
    JwtHmacKey key = factory.createKey(keyFormat);
    assertThat(key.getKeyValue()).hasSize(keyFormat.getKeySize());
    assertThat(key.getHashType()).isEqualTo(keyFormat.getHashType());
  }

  @Test
  public void createKey_multipleTimes() throws Exception {
    JwtHmacKeyFormat keyFormat = makeJwtHmacKeyFormat(32, HashType.SHA256);
    int numKeys = 100;
    Set<String> keys = new TreeSet<String>();
    for (int i = 0; i < numKeys; ++i) {
      keys.add(TestUtil.hexEncode(factory.createKey(keyFormat).getKeyValue().toByteArray()));
    }
    assertThat(keys).hasSize(numKeys);
  }

  @Test
  public void validateKey_wrongVersion_throws() throws Exception {
    JwtHmacKey validKey = factory.createKey(makeJwtHmacKeyFormat(32, HashType.SHA256));
    try {
      manager.validateKey(JwtHmacKey.newBuilder(validKey).setVersion(1).build());
      fail();
    } catch (GeneralSecurityException e) {
      // expected
    }
  }

  @Test
  public void validateKey_notValid_throws() throws Exception {
    JwtHmacKey validKey = factory.createKey(makeJwtHmacKeyFormat(32, HashType.SHA256));
    try {
      manager.validateKey(
          JwtHmacKey.newBuilder(validKey)
              .setKeyValue(ByteString.copyFrom(Random.randBytes(31)))
              .build());
      fail();
    } catch (GeneralSecurityException e) {
      // expected
    }
  }

  @Test
  public void getPrimitive_worksForSha256() throws Exception {
    JwtHmacKey validKey = factory.createKey(makeJwtHmacKeyFormat(32, HashType.SHA256));
    JwtMac managerMac = manager.getPrimitive(validKey, JwtMac.class);
    JwtMac directMac =
        new JwtHmac("HS256", new SecretKeySpec(validKey.getKeyValue().toByteArray(), "HMAC"));
    ToBeSignedJwt token = new ToBeSignedJwt.Builder().build();
    JwtValidator validator = new JwtValidator.Builder().build();
    managerMac.verifyCompact(directMac.createCompact(token), validator);
  }

  @Test
  public void getPrimitive_worksForSha384() throws Exception {
    JwtHmacKey validKey = factory.createKey(makeJwtHmacKeyFormat(32, HashType.SHA384));
    JwtMac managerMac = manager.getPrimitive(validKey, JwtMac.class);
    JwtMac directMac =
        new JwtHmac("HS384", new SecretKeySpec(validKey.getKeyValue().toByteArray(), "HMAC"));
    ToBeSignedJwt token = new ToBeSignedJwt.Builder().build();
    JwtValidator validator = new JwtValidator.Builder().build();
    managerMac.verifyCompact(directMac.createCompact(token), validator);
  }

  @Test
  public void getPrimitive_worksForSha512() throws Exception {
    JwtHmacKey validKey = factory.createKey(makeJwtHmacKeyFormat(32, HashType.SHA512));
    JwtMac managerMac = manager.getPrimitive(validKey, JwtMac.class);
    JwtMac directMac =
        new JwtHmac("HS512", new SecretKeySpec(validKey.getKeyValue().toByteArray(), "HMAC"));
    ToBeSignedJwt token = new ToBeSignedJwt.Builder().build();
    JwtValidator validator = new JwtValidator.Builder().build();
    managerMac.verifyCompact(directMac.createCompact(token), validator);
  }

  @Test
  public void testDeriveKey_shouldThrowUnsupportedException() throws Exception {
    assertThrows(
        UnsupportedOperationException.class,
        () ->
            factory.deriveKey(
                JwtHmacKeyFormat.newBuilder().build(),
                new ByteArrayInputStream(Random.randBytes(100))));
  }

  @Test
  public void testHs256Template() throws Exception {
    KeyTemplate template = JwtHmacKeyManager.hs256Template();
    assertThat(template.getTypeUrl()).isEqualTo(manager.getKeyType());
    assertThat(template.getOutputPrefixType()).isEqualTo(KeyTemplate.OutputPrefixType.RAW);
    JwtHmacKeyFormat format =
        JwtHmacKeyFormat.parseFrom(template.getValue(), ExtensionRegistryLite.getEmptyRegistry());

    assertThat(format.getKeySize()).isEqualTo(32);
    assertThat(format.getHashType()).isEqualTo(HashType.SHA256);
  }

  @Test
  public void testHs384Template() throws Exception {
    KeyTemplate template = JwtHmacKeyManager.hs384Template();
    assertThat(template.getTypeUrl()).isEqualTo(new JwtHmacKeyManager().getKeyType());
    assertThat(template.getOutputPrefixType()).isEqualTo(KeyTemplate.OutputPrefixType.RAW);
    JwtHmacKeyFormat format =
        JwtHmacKeyFormat.parseFrom(template.getValue(), ExtensionRegistryLite.getEmptyRegistry());

    assertThat(format.getKeySize()).isEqualTo(48);
    assertThat(format.getHashType()).isEqualTo(HashType.SHA384);
  }

  @Test
  public void testHs512Template() throws Exception {
    KeyTemplate template = JwtHmacKeyManager.hs512Template();
    assertThat(template.getTypeUrl()).isEqualTo(new JwtHmacKeyManager().getKeyType());
    assertThat(template.getOutputPrefixType()).isEqualTo(KeyTemplate.OutputPrefixType.RAW);
    JwtHmacKeyFormat format =
        JwtHmacKeyFormat.parseFrom(template.getValue(), ExtensionRegistryLite.getEmptyRegistry());

    assertThat(format.getKeySize()).isEqualTo(64);
    assertThat(format.getHashType()).isEqualTo(HashType.SHA512);
  }

  @Test
  public void testKeyTemplateAndManagerCompatibility() throws Exception {
    testKeyTemplateCompatible(manager, JwtHmacKeyManager.hs256Template());
    testKeyTemplateCompatible(manager, JwtHmacKeyManager.hs384Template());
    testKeyTemplateCompatible(manager, JwtHmacKeyManager.hs512Template());
  }
}
