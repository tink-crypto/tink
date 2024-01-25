// Copyright 2018 Google LLC
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

import com.google.crypto.tink.InsecureSecretKeyAccess;
import com.google.crypto.tink.KeyTemplate;
import com.google.crypto.tink.KeyTemplates;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.Parameters;
import com.google.crypto.tink.PublicKeySign;
import com.google.crypto.tink.PublicKeyVerify;
import com.google.crypto.tink.TinkProtoKeysetFormat;
import com.google.crypto.tink.internal.KeyManagerRegistry;
import com.google.crypto.tink.signature.internal.testing.RsaSsaPkcs1TestUtil;
import com.google.crypto.tink.signature.internal.testing.SignatureTestVector;
import com.google.crypto.tink.subtle.Hex;
import com.google.crypto.tink.testing.TestUtil;
import java.math.BigInteger;
import java.util.Set;
import java.util.TreeSet;
import javax.annotation.Nullable;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.experimental.theories.DataPoints;
import org.junit.experimental.theories.FromDataPoints;
import org.junit.experimental.theories.Theories;
import org.junit.experimental.theories.Theory;
import org.junit.runner.RunWith;

/** Unit tests for RsaSsaPkcs1SignKeyManager. */
@RunWith(Theories.class)
public class RsaSsaPkcs1SignKeyManagerTest {

  @BeforeClass
  public static void beforeClass() throws Exception {
    RsaSsaPkcs1SignKeyManager.registerPair(/* newKeyAllowed= */ true);
    PublicKeySignWrapper.register();
    PublicKeyVerifyWrapper.register();
  }

  @Test
  public void createKey_smallKey_works() throws Exception {
    if (TestUtil.isTsan()) {
      // factory.createKey is too slow in Tsan.
      return;
    }
    RsaSsaPkcs1Parameters parameters =
        RsaSsaPkcs1Parameters.builder()
            .setModulusSizeBits(2048)
            .setPublicExponent(RsaSsaPkcs1Parameters.F4)
            .setHashType(RsaSsaPkcs1Parameters.HashType.SHA256)
            .setVariant(RsaSsaPkcs1Parameters.Variant.NO_PREFIX)
            .build();
    KeysetHandle handle = KeysetHandle.generateNew(parameters);
    com.google.crypto.tink.Key key = handle.getAt(0).getKey();
    assertThat(key).isInstanceOf(com.google.crypto.tink.signature.RsaSsaPkcs1PrivateKey.class);
    com.google.crypto.tink.signature.RsaSsaPkcs1PrivateKey privateKey =
        (com.google.crypto.tink.signature.RsaSsaPkcs1PrivateKey) key;

    assertThat(privateKey.getPublicKey().getParameters()).isEqualTo(parameters);
    assertThat(privateKey.getPublicKey().getModulus().bitLength()).isEqualTo(2048);
  }

  @Test
  public void createKey_alwaysNewElement() throws Exception {
    if (TestUtil.isTsan()) {
      // factory.createKey is too slow in Tsan.
      return;
    }

    RsaSsaPkcs1Parameters parameters =
        RsaSsaPkcs1Parameters.builder()
            .setModulusSizeBits(2048)
            .setPublicExponent(RsaSsaPkcs1Parameters.F4)
            .setHashType(RsaSsaPkcs1Parameters.HashType.SHA256)
            .setVariant(RsaSsaPkcs1Parameters.Variant.TINK)
            .build();
    Set<BigInteger> primes = new TreeSet<>();
    // Calls newKey multiple times and make sure that they generate different keys -- takes about a
    // second per key.
    int numTests = 5;
    for (int i = 0; i < numTests; i++) {
      KeysetHandle handle = KeysetHandle.generateNew(parameters);
      assertThat(handle.size()).isEqualTo(1);
      com.google.crypto.tink.signature.RsaSsaPkcs1PrivateKey key =
          (com.google.crypto.tink.signature.RsaSsaPkcs1PrivateKey) handle.getAt(0).getKey();
      primes.add(key.getPrimeP().getBigInteger(InsecureSecretKeyAccess.get()));
      primes.add(key.getPrimeQ().getBigInteger(InsecureSecretKeyAccess.get()));
    }
    assertThat(primes).hasSize(2 * numTests);
  }

  @Test
  public void testRsa3072SsaPkcs1Sha256F4Template() throws Exception {
    KeyTemplate template = RsaSsaPkcs1SignKeyManager.rsa3072SsaPkcs1Sha256F4Template();
    assertThat(template.toParameters())
        .isEqualTo(
            RsaSsaPkcs1Parameters.builder()
                .setModulusSizeBits(3072)
                .setPublicExponent(RsaSsaPkcs1Parameters.F4)
                .setHashType(RsaSsaPkcs1Parameters.HashType.SHA256)
                .setVariant(RsaSsaPkcs1Parameters.Variant.TINK)
                .build());
  }

  @Test
  public void testRawRsa3072SsaPkcs1Sha256F4Template() throws Exception {
    KeyTemplate template = RsaSsaPkcs1SignKeyManager.rawRsa3072SsaPkcs1Sha256F4Template();
    assertThat(template.toParameters())
        .isEqualTo(
            RsaSsaPkcs1Parameters.builder()
                .setModulusSizeBits(3072)
                .setPublicExponent(RsaSsaPkcs1Parameters.F4)
                .setHashType(RsaSsaPkcs1Parameters.HashType.SHA256)
                .setVariant(RsaSsaPkcs1Parameters.Variant.NO_PREFIX)
                .build());
  }

  @Test
  public void testRsa4096SsaPkcs1Sha512F4Template() throws Exception {
    KeyTemplate template = RsaSsaPkcs1SignKeyManager.rsa4096SsaPkcs1Sha512F4Template();
    assertThat(template.toParameters())
        .isEqualTo(
            RsaSsaPkcs1Parameters.builder()
                .setModulusSizeBits(4096)
                .setPublicExponent(RsaSsaPkcs1Parameters.F4)
                .setHashType(RsaSsaPkcs1Parameters.HashType.SHA512)
                .setVariant(RsaSsaPkcs1Parameters.Variant.TINK)
                .build());
  }

  @Test
  public void testRawRsa4096SsaPkcs1Sha512F4Template() throws Exception {
    KeyTemplate template = RsaSsaPkcs1SignKeyManager.rawRsa4096SsaPkcs1Sha512F4Template();
    assertThat(template.toParameters())
        .isEqualTo(
            RsaSsaPkcs1Parameters.builder()
                .setModulusSizeBits(4096)
                .setPublicExponent(RsaSsaPkcs1Parameters.F4)
                .setHashType(RsaSsaPkcs1Parameters.HashType.SHA512)
                .setVariant(RsaSsaPkcs1Parameters.Variant.NO_PREFIX)
                .build());
  }

  @Test
  public void testRsa3072SsaPkcs1Sha256F4TemplateWithManager() throws Exception {
    if (TestUtil.isTsan()) {
      // factory.createKey is too slow in Tsan.
      return;
    }
    Parameters p = RsaSsaPkcs1SignKeyManager.rsa3072SsaPkcs1Sha256F4Template().toParameters();
    assertThat(KeysetHandle.generateNew(p).getAt(0).getKey().getParameters()).isEqualTo(p);
  }

  @Test
  public void testRawRsa3072SsaPkcs1Sha256F4TemplateWithManager() throws Exception {
    if (TestUtil.isTsan()) {
      // factory.createKey is too slow in Tsan.
      return;
    }
    Parameters p = RsaSsaPkcs1SignKeyManager.rawRsa3072SsaPkcs1Sha256F4Template().toParameters();
    assertThat(KeysetHandle.generateNew(p).getAt(0).getKey().getParameters()).isEqualTo(p);
  }

  @Test
  public void testRsa4096SsaPkcs1Sha512F4TemplateWithManager() throws Exception {
    if (TestUtil.isTsan()) {
      // factory.createKey is too slow in Tsan.
      return;
    }
    Parameters p = RsaSsaPkcs1SignKeyManager.rsa4096SsaPkcs1Sha512F4Template().toParameters();
    assertThat(KeysetHandle.generateNew(p).getAt(0).getKey().getParameters()).isEqualTo(p);
  }

  @Test
  public void testRawRsa4096SsaPkcs1Sha512F4TemplateWithManager() throws Exception {
    if (TestUtil.isTsan()) {
      // factory.createKey is too slow in Tsan.
      return;
    }
    Parameters p = RsaSsaPkcs1SignKeyManager.rawRsa4096SsaPkcs1Sha512F4Template().toParameters();
    assertThat(KeysetHandle.generateNew(p).getAt(0).getKey().getParameters()).isEqualTo(p);
  }

  @DataPoints("templateNames")
  public static final String[] KEY_TEMPLATES =
      new String[] {
        "RSA_SSA_PKCS1_3072_SHA256_F4",
        "RSA_SSA_PKCS1_3072_SHA256_F4_RAW",
        "RSA_SSA_PKCS1_4096_SHA512_F4",
        "RSA_SSA_PKCS1_4096_SHA512_F4_RAW",
        "RSA_SSA_PKCS1_3072_SHA256_F4_WITHOUT_PREFIX"
      };

  @Theory
  public void testTemplates(@FromDataPoints("templateNames") String templateName) throws Exception {
    if (TestUtil.isTsan()) {
      // factory.createKey is too slow in Tsan.
      return;
    }
    KeysetHandle h = KeysetHandle.generateNew(KeyTemplates.get(templateName));
    assertThat(h.size()).isEqualTo(1);
    assertThat(h.getAt(0).getKey().getParameters())
        .isEqualTo(KeyTemplates.get(templateName).toParameters());
  }

  @DataPoints("testVectors")
  public static final SignatureTestVector[] SIGNATURE_TEST_VECTORS =
      RsaSsaPkcs1TestUtil.createRsaSsaPkcs1TestVectors();

  @Theory
  public void test_computeSignatureInTestVector(
      @FromDataPoints("testVectors") SignatureTestVector v) throws Exception {
    KeysetHandle.Builder.Entry entry = KeysetHandle.importKey(v.getPrivateKey()).makePrimary();
    @Nullable Integer id = v.getPrivateKey().getIdRequirementOrNull();
    if (id == null) {
      entry.withRandomId();
    } else {
      entry.withFixedId(id);
    }
    KeysetHandle handle = KeysetHandle.newBuilder().addEntry(entry).build();
    PublicKeySign signer = handle.getPrimitive(PublicKeySign.class);
    byte[] signature = signer.sign(v.getMessage());
    assertThat(Hex.encode(signature)).isEqualTo(Hex.encode(v.getSignature()));
  }

  @Theory
  public void test_validateSignatureInTestVector(
      @FromDataPoints("testVectors") SignatureTestVector v) throws Exception {
    KeysetHandle.Builder.Entry entry = KeysetHandle.importKey(v.getPrivateKey()).makePrimary();
    @Nullable Integer id = v.getPrivateKey().getIdRequirementOrNull();
    if (id == null) {
      entry.withRandomId();
    } else {
      entry.withFixedId(id);
    }
    KeysetHandle handle = KeysetHandle.newBuilder().addEntry(entry).build();
    PublicKeyVerify verifier = handle.getPublicKeysetHandle().getPrimitive(PublicKeyVerify.class);
    verifier.verify(v.getSignature(), v.getMessage());
  }

  @Test
  public void test_serializeAndParse_works() throws Exception {
    SignatureTestVector testVector = SIGNATURE_TEST_VECTORS[0];
    com.google.crypto.tink.signature.RsaSsaPkcs1PrivateKey key =
        (com.google.crypto.tink.signature.RsaSsaPkcs1PrivateKey) testVector.getPrivateKey();
    KeysetHandle.Builder.Entry entry = KeysetHandle.importKey(key).withFixedId(1216).makePrimary();
    KeysetHandle handle = KeysetHandle.newBuilder().addEntry(entry).build();

    byte[] serializedHandle =
        TinkProtoKeysetFormat.serializeKeyset(handle, InsecureSecretKeyAccess.get());
    KeysetHandle parsedHandle =
        TinkProtoKeysetFormat.parseKeyset(serializedHandle, InsecureSecretKeyAccess.get());
    assertThat(parsedHandle.equalsKeyset(handle)).isTrue();
  }

  @Test
  public void testKeyManagerRegistered() throws Exception {
    assertThat(
            KeyManagerRegistry.globalInstance()
                .getKeyManager(
                    "type.googleapis.com/google.crypto.tink.RsaSsaPkcs1PrivateKey",
                    PublicKeySign.class))
        .isNotNull();
  }
}
