// Copyright 2017 Google LLC
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

package com.google.crypto.tink.signature;

import static com.google.common.truth.Truth.assertThat;
import static org.junit.Assert.fail;

import com.google.crypto.tink.TestUtil;
import com.google.crypto.tink.proto.EcdsaKeyFormat;
import com.google.crypto.tink.proto.EcdsaParams;
import com.google.crypto.tink.proto.EcdsaPrivateKey;
import com.google.crypto.tink.proto.EcdsaPublicKey;
import com.google.crypto.tink.proto.EcdsaSignatureEncoding;
import com.google.crypto.tink.proto.EllipticCurveType;
import com.google.crypto.tink.proto.HashType;
import com.google.crypto.tink.proto.KeyData.KeyMaterialType;
import java.security.GeneralSecurityException;
import java.util.Set;
import java.util.TreeSet;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Unit tests for EcdsaSignKeyManager. */
@RunWith(JUnit4.class)
public class EcdsaSignKeyManagerTest {
  private final EcdsaSignKeyManager manager = new EcdsaSignKeyManager();
  private final EcdsaSignKeyManager.KeyFactory<EcdsaKeyFormat, EcdsaPrivateKey> factory =
      manager.keyFactory();

  private static EcdsaKeyFormat createKeyFormat(
      HashType hashType, EllipticCurveType curveType, EcdsaSignatureEncoding encoding) {
    return EcdsaKeyFormat.newBuilder()
        .setParams(
            EcdsaParams.newBuilder()
                .setHashType(hashType)
                .setCurve(curveType)
                .setEncoding(encoding))
        .build();
  }

  @Test
  public void basics() throws Exception {
    assertThat(manager.getKeyType())
        .isEqualTo("type.googleapis.com/google.crypto.tink.EcdsaPrivateKey");
    assertThat(manager.getVersion()).isEqualTo(0);
    assertThat(manager.keyMaterialType())
        .isEqualTo(KeyMaterialType.ASYMMETRIC_PRIVATE);
  }

  @Test
  public void validateKeyFormat_empty() throws Exception {
    try {
      factory.validateKeyFormat(EcdsaKeyFormat.getDefaultInstance());
      fail();
    } catch (GeneralSecurityException e) {
      // expected
    }
  }

  @Test
  public void validateKeyFormat_valid() throws Exception {
    // SHA256 NIST_P256 DER
    factory.validateKeyFormat(
        createKeyFormat(HashType.SHA256, EllipticCurveType.NIST_P256, EcdsaSignatureEncoding.DER));
    // SHA256 NIST_P256 IEEE_P1363
    factory.validateKeyFormat(
        createKeyFormat(
            HashType.SHA256, EllipticCurveType.NIST_P256, EcdsaSignatureEncoding.IEEE_P1363));
    // SHA384 NIST_P384 DER
    factory.validateKeyFormat(
        createKeyFormat(HashType.SHA384, EllipticCurveType.NIST_P384, EcdsaSignatureEncoding.DER));
    // SHA384 NIST_P384 IEEE_P1363
    factory.validateKeyFormat(
        createKeyFormat(
            HashType.SHA384, EllipticCurveType.NIST_P384, EcdsaSignatureEncoding.IEEE_P1363));
    // SHA512 NIST_P384 DER
    factory.validateKeyFormat(
        createKeyFormat(HashType.SHA512, EllipticCurveType.NIST_P384, EcdsaSignatureEncoding.DER));
    // SHA512 NIST_P384 IEEE_P1363
    factory.validateKeyFormat(
        createKeyFormat(
            HashType.SHA512, EllipticCurveType.NIST_P384, EcdsaSignatureEncoding.IEEE_P1363));
    // SHA512 NIST_P521 DER
    factory.validateKeyFormat(
        createKeyFormat(HashType.SHA512, EllipticCurveType.NIST_P521, EcdsaSignatureEncoding.DER));
    // SHA512 NIST_P521 IEEE_P1363
    factory.validateKeyFormat(
        createKeyFormat(
            HashType.SHA512, EllipticCurveType.NIST_P521, EcdsaSignatureEncoding.IEEE_P1363));
  }

  @Test
  public void validateKeyFormat_noSha1() throws Exception {
    try {
      factory.validateKeyFormat(
          createKeyFormat(HashType.SHA1, EllipticCurveType.NIST_P256, EcdsaSignatureEncoding.DER));
      fail();
    } catch (GeneralSecurityException expected) {
      // Expected
    }
    try {
      factory.validateKeyFormat(
          createKeyFormat(HashType.SHA1, EllipticCurveType.NIST_P384, EcdsaSignatureEncoding.DER));
      fail();
    } catch (GeneralSecurityException expected) {
      // Expected
    }
    try {
      factory.validateKeyFormat(
          createKeyFormat(HashType.SHA1, EllipticCurveType.NIST_P521, EcdsaSignatureEncoding.DER));
      fail();
    } catch (GeneralSecurityException expected) {
      // Expected
    }
  }

  @Test
  public void validateKeyFormat_p384NotWithSha256() throws Exception {
    try {
      factory.validateKeyFormat(
          createKeyFormat(
              HashType.SHA256, EllipticCurveType.NIST_P384, EcdsaSignatureEncoding.DER));
      fail();
    } catch (GeneralSecurityException expected) {
      // Expected
    }
  }

  @Test
  public void validateKeyFormat_p521OnlyWithSha512() throws Exception {
    try {
      factory.validateKeyFormat(
          createKeyFormat(
              HashType.SHA256, EllipticCurveType.NIST_P521, EcdsaSignatureEncoding.DER));
      fail();
    } catch (GeneralSecurityException expected) {
      // Expected
    }
    try {
      factory.validateKeyFormat(
          createKeyFormat(
              HashType.SHA384, EllipticCurveType.NIST_P521, EcdsaSignatureEncoding.DER));
      fail();
    } catch (GeneralSecurityException expected) {
      // Expected
    }
  }

  @Test
  public void validateKeyFormat_unkownsProhibited() throws Exception {
    try {
      factory.validateKeyFormat(
          createKeyFormat(
              HashType.UNKNOWN_HASH, EllipticCurveType.NIST_P256, EcdsaSignatureEncoding.DER));
      fail();
    } catch (GeneralSecurityException expected) {
      // Expected
    }
    try {
      factory.validateKeyFormat(
          createKeyFormat(
              HashType.SHA256, EllipticCurveType.UNKNOWN_CURVE, EcdsaSignatureEncoding.DER));
      fail();
    } catch (GeneralSecurityException expected) {
      // Expected
    }
    try {
      factory.validateKeyFormat(
          createKeyFormat(
              HashType.SHA256,
              EllipticCurveType.NIST_P256,
              EcdsaSignatureEncoding.UNKNOWN_ENCODING));
      fail();
    } catch (GeneralSecurityException expected) {
      // Expected
    }
  }

  @Test
  public void validateKey_empty() throws Exception {
    try {
      manager.validateKey(EcdsaPrivateKey.getDefaultInstance());
      fail();
    } catch (GeneralSecurityException e) {
      // expected
    }
  }

  /** Tests that a public key is extracted properly from a private key. */
  @Test
  public void getPublicKey_checkValues() throws Exception {
    EcdsaPrivateKey privateKey =
        factory.createKey(
            createKeyFormat(
                HashType.SHA256, EllipticCurveType.NIST_P256, EcdsaSignatureEncoding.DER));
    EcdsaPublicKey publicKey = manager.getPublicKey(privateKey);

    assertThat(publicKey).isEqualTo(privateKey.getPublicKey());
  }

  // Tests that generated keys have an adequate size. This is best-effort because keys might
  // have leading zeros that are stripped off. These tests are flaky; the probability of
  // failure is 2^-64 which happens when a key has 8 leading zeros.
  @Test
  public void createKey_NISTP256_keySize() throws Exception {
    EcdsaPrivateKey privateKey =
        factory.createKey(
            createKeyFormat(
                HashType.SHA256, EllipticCurveType.NIST_P256, EcdsaSignatureEncoding.DER));
    assertThat(privateKey.getKeyValue().size()).isAtLeast(256 / 8 - 8);
    assertThat(privateKey.getKeyValue().size()).isAtMost(256 / 8 + 1);
  }

  // Tests that generated keys have an adequate size. This is best-effort because keys might
  // have leading zeros that are stripped off. These tests are flaky; the probability of
  // failure is 2^-64 which happens when a key has 8 leading zeros.
  @Test
  public void createKey_NISTP384_keySize() throws Exception {
    EcdsaPrivateKey privateKey =
        factory.createKey(
            createKeyFormat(
                HashType.SHA384, EllipticCurveType.NIST_P384, EcdsaSignatureEncoding.DER));
    assertThat(privateKey.getKeyValue().size()).isAtLeast(384 / 8 - 8);
    assertThat(privateKey.getKeyValue().size()).isAtMost(384 / 8 + 1);
  }

  // Tests that generated keys have an adequate size. This is best-effort because keys might
  // have leading zeros that are stripped off. These tests are flaky; the probability of
  // failure is 2^-64 which happens when a key has 8 leading zeros.
  @Test
  public void createKey_NISTP521_keySize() throws Exception {
    EcdsaPrivateKey privateKey =
        factory.createKey(
            createKeyFormat(
                HashType.SHA512, EllipticCurveType.NIST_P521, EcdsaSignatureEncoding.DER));
    assertThat(privateKey.getKeyValue().size()).isAtLeast(521 / 8 - 8);
    assertThat(privateKey.getKeyValue().size()).isAtMost(521 / 8 + 1);
  }

  @Test
  public void createKey_NISTP256_differentValues() throws Exception {
    EcdsaKeyFormat format =
        createKeyFormat(HashType.SHA256, EllipticCurveType.NIST_P256, EcdsaSignatureEncoding.DER);
    Set<String> keys = new TreeSet<>();
    int numTests = 100;
    for (int i = 0; i < numTests; i++) {
      keys.add(TestUtil.hexEncode(factory.createKey(format).getKeyValue().toByteArray()));
    }
    assertThat(keys).hasSize(numTests);
  }

  @Test
  public void createKey_NISTP384_differentValues() throws Exception {
    EcdsaKeyFormat format =
        createKeyFormat(HashType.SHA384, EllipticCurveType.NIST_P384, EcdsaSignatureEncoding.DER);
    Set<String> keys = new TreeSet<>();
    int numTests = 100;
    for (int i = 0; i < numTests; i++) {
      keys.add(TestUtil.hexEncode(factory.createKey(format).getKeyValue().toByteArray()));
    }
    assertThat(keys).hasSize(numTests);
  }


  @Test
  public void createKey_NISTP521_differentValues() throws Exception {
    EcdsaKeyFormat format =
        createKeyFormat(HashType.SHA512, EllipticCurveType.NIST_P521, EcdsaSignatureEncoding.DER);
    Set<String> keys = new TreeSet<>();
    int numTests = 100;
    for (int i = 0; i < numTests; i++) {
      keys.add(TestUtil.hexEncode(factory.createKey(format).getKeyValue().toByteArray()));
    }
    assertThat(keys).hasSize(numTests);
  }
}
