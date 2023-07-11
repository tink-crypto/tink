// Copyright 2018 Google Inc.
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
import static com.google.crypto.tink.testing.KeyTypeManagerTestUtil.testKeyTemplateCompatible;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThrows;

import com.google.crypto.tink.KeyTemplate;
import com.google.crypto.tink.KeyTemplates;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.PublicKeySign;
import com.google.crypto.tink.PublicKeyVerify;
import com.google.crypto.tink.internal.KeyTypeManager;
import com.google.crypto.tink.proto.HashType;
import com.google.crypto.tink.proto.KeyData.KeyMaterialType;
import com.google.crypto.tink.proto.RsaSsaPkcs1KeyFormat;
import com.google.crypto.tink.proto.RsaSsaPkcs1Params;
import com.google.crypto.tink.proto.RsaSsaPkcs1PrivateKey;
import com.google.crypto.tink.proto.RsaSsaPkcs1PublicKey;
import com.google.crypto.tink.signature.internal.SigUtil;
import com.google.crypto.tink.subtle.EngineFactory;
import com.google.crypto.tink.subtle.Hex;
import com.google.crypto.tink.subtle.Random;
import com.google.crypto.tink.subtle.RsaSsaPkcs1VerifyJce;
import com.google.crypto.tink.testing.TestUtil;
import com.google.protobuf.ByteString;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.RSAKeyGenParameterSpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.Set;
import java.util.TreeSet;
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
  }

  private final RsaSsaPkcs1SignKeyManager manager = new RsaSsaPkcs1SignKeyManager();
  private final KeyTypeManager.KeyFactory<RsaSsaPkcs1KeyFormat, RsaSsaPkcs1PrivateKey> factory =
      manager.keyFactory();

  private static RsaSsaPkcs1KeyFormat createKeyFormat(
      HashType hashType, int modulusSizeInBits, BigInteger publicExponent) {
    return RsaSsaPkcs1KeyFormat.newBuilder()
        .setParams(RsaSsaPkcs1Params.newBuilder().setHashType(hashType))
        .setModulusSizeInBits(modulusSizeInBits)
        .setPublicExponent(ByteString.copyFrom(publicExponent.toByteArray()))
        .build();
  }

  private static RsaSsaPkcs1KeyFormat validKeyFormat() {
    return createKeyFormat(HashType.SHA256, 3072, RSAKeyGenParameterSpec.F4);
  }

  @Test
  public void basics() throws Exception {
    assertThat(manager.getKeyType())
        .isEqualTo("type.googleapis.com/google.crypto.tink.RsaSsaPkcs1PrivateKey");
    assertThat(manager.getVersion()).isEqualTo(0);
    assertThat(manager.keyMaterialType()).isEqualTo(KeyMaterialType.ASYMMETRIC_PRIVATE);
  }

  @Test
  public void validateKeyFormat_empty() throws Exception {
    assertThrows(
        GeneralSecurityException.class,
        () -> factory.validateKeyFormat(RsaSsaPkcs1KeyFormat.getDefaultInstance()));
  }

  @Test
  public void validateKeyFormat_valid() throws Exception {
    RsaSsaPkcs1KeyFormat format = validKeyFormat();
    factory.validateKeyFormat(format);
  }

  @Test
  public void validateKeyFormat_sha512Allowed() throws Exception {
    RsaSsaPkcs1KeyFormat format = createKeyFormat(HashType.SHA512, 3072, RSAKeyGenParameterSpec.F4);
    factory.validateKeyFormat(format);
  }

  @Test
  public void validateKeyFormat_sha384Allowed() throws Exception {
    // TODO(b/140410067): Check if SHA384 should be allowed.
    RsaSsaPkcs1KeyFormat format = createKeyFormat(HashType.SHA384, 3072, RSAKeyGenParameterSpec.F4);
    factory.validateKeyFormat(format);
  }

  @Test
  public void validateKeyFormat_sha1Disallowed() throws Exception {
    RsaSsaPkcs1KeyFormat format = createKeyFormat(HashType.SHA1, 3072, RSAKeyGenParameterSpec.F4);
    assertThrows(GeneralSecurityException.class, () -> factory.validateKeyFormat(format));
  }

  @Test
  public void validateKeyFormat_unknownHashDisallowed() throws Exception {
    RsaSsaPkcs1KeyFormat format =
        createKeyFormat(HashType.UNKNOWN_HASH, 3072, RSAKeyGenParameterSpec.F4);
    assertThrows(GeneralSecurityException.class, () -> factory.validateKeyFormat(format));
  }

  @Test
  public void validateKeyFormat_smallModulusDisallowed_throws() throws Exception {
    RsaSsaPkcs1KeyFormat format = createKeyFormat(HashType.SHA512, 1024, RSAKeyGenParameterSpec.F4);
    assertThrows(GeneralSecurityException.class, () -> factory.validateKeyFormat(format));
  }

  private static void checkConsistency(
      RsaSsaPkcs1PrivateKey privateKey, RsaSsaPkcs1KeyFormat keyFormat) {
    assertThat(privateKey.getPublicKey().getParams()).isEqualTo(keyFormat.getParams());
    assertThat(privateKey.getPublicKey().getE()).isEqualTo(keyFormat.getPublicExponent());
    assertThat(privateKey.getPublicKey().getN().toByteArray().length)
        .isGreaterThan(keyFormat.getModulusSizeInBits() / 8);
  }

  private void checkKey(RsaSsaPkcs1PrivateKey privateKey) throws Exception {
    RsaSsaPkcs1PublicKey publicKey = privateKey.getPublicKey();
    assertThat(privateKey.getVersion()).isEqualTo(0);
    assertThat(publicKey.getVersion()).isEqualTo(privateKey.getVersion());

    BigInteger p = new BigInteger(1, privateKey.getP().toByteArray());
    BigInteger q = new BigInteger(1, privateKey.getQ().toByteArray());
    BigInteger n = new BigInteger(1, privateKey.getPublicKey().getN().toByteArray());
    BigInteger d = new BigInteger(1, privateKey.getD().toByteArray());
    BigInteger dp = new BigInteger(1, privateKey.getDp().toByteArray());
    BigInteger dq = new BigInteger(1, privateKey.getDq().toByteArray());
    BigInteger crt = new BigInteger(1, privateKey.getCrt().toByteArray());
    assertThat(p).isGreaterThan(BigInteger.ONE);
    assertThat(q).isGreaterThan(BigInteger.ONE);
    assertEquals(n, p.multiply(q));
    assertEquals(dp, d.mod(p.subtract(BigInteger.ONE)));
    assertEquals(dq, d.mod(q.subtract(BigInteger.ONE)));
    assertEquals(crt, q.modInverse(p));
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
  public void createKey_largeKey() throws Exception {
    if (TestUtil.isTsan()) {
      // factory.createKey is too slow in Tsan.
      return;
    }

    RsaSsaPkcs1KeyFormat format = createKeyFormat(HashType.SHA512, 4096, RSAKeyGenParameterSpec.F4);
    RsaSsaPkcs1PrivateKey key = factory.createKey(format);
    checkConsistency(key, format);
    checkKey(key);
  }

  @Test
  public void createKey_alwaysNewElement() throws Exception {
    if (TestUtil.isTsan()) {
      // factory.createKey is too slow in Tsan.
      return;
    }

    RsaSsaPkcs1KeyFormat format = createKeyFormat(HashType.SHA256, 3072, RSAKeyGenParameterSpec.F4);
    Set<String> keys = new TreeSet<>();
    // Calls newKey multiple times and make sure that they generate different keys -- takes about a
    // second per key.
    int numTests = 5;
    for (int i = 0; i < numTests; i++) {
      RsaSsaPkcs1PrivateKey key = factory.createKey(format);
      keys.add(Hex.encode(key.getQ().toByteArray()));
      keys.add(Hex.encode(key.getP().toByteArray()));
    }
    assertThat(keys).hasSize(2 * numTests);
  }

  @Test
  public void getPublicKey_correctValues() throws Exception {
    if (TestUtil.isTsan()) {
      // factory.createKey is too slow in Tsan.
      return;
    }

    RsaSsaPkcs1KeyFormat format = createKeyFormat(HashType.SHA256, 3072, RSAKeyGenParameterSpec.F4);
    RsaSsaPkcs1PrivateKey key = factory.createKey(format);
    assertThat(manager.getPublicKey(key)).isEqualTo(key.getPublicKey());
  }

  @Test
  public void createPrimitive() throws Exception {
    if (TestUtil.isTsan()) {
      // factory.createKey is too slow in Tsan.
      return;
    }

    RsaSsaPkcs1KeyFormat format = createKeyFormat(HashType.SHA256, 3072, RSAKeyGenParameterSpec.F4);
    RsaSsaPkcs1PrivateKey key = factory.createKey(format);
    PublicKeySign signer = manager.getPrimitive(key, PublicKeySign.class);

    KeyFactory kf = EngineFactory.KEY_FACTORY.getInstance("RSA");
    BigInteger modulus = new BigInteger(1, key.getPublicKey().getN().toByteArray());
    BigInteger exponent = new BigInteger(1, key.getPublicKey().getE().toByteArray());
    RSAPublicKey publicKey =
        (RSAPublicKey) kf.generatePublic(new RSAPublicKeySpec(modulus, exponent));
    PublicKeyVerify verifier =
        new RsaSsaPkcs1VerifyJce(
            publicKey, SigUtil.toHashType(key.getPublicKey().getParams().getHashType()));

    byte[] message = Random.randBytes(135);
    verifier.verify(signer.sign(message), message);
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
    testKeyTemplateCompatible(manager, RsaSsaPkcs1SignKeyManager.rsa3072SsaPkcs1Sha256F4Template());
  }

  @Test
  public void testRawRsa3072SsaPkcs1Sha256F4TemplateWithManager() throws Exception {
    testKeyTemplateCompatible(
        manager, RsaSsaPkcs1SignKeyManager.rawRsa3072SsaPkcs1Sha256F4Template());
  }

  @Test
  public void testRsa4096SsaPkcs1Sha512F4TemplateWithManager() throws Exception {
    testKeyTemplateCompatible(manager, RsaSsaPkcs1SignKeyManager.rsa4096SsaPkcs1Sha512F4Template());
  }

  @Test
  public void testRawRsa4096SsaPkcs1Sha512F4TemplateWithManager() throws Exception {
    testKeyTemplateCompatible(
        manager, RsaSsaPkcs1SignKeyManager.rawRsa4096SsaPkcs1Sha512F4Template());
  }

  @Test
  public void createCorruptedModulusPrimitive_throws() throws Exception {

    RsaSsaPkcs1KeyFormat format = createKeyFormat(HashType.SHA512, 4096, RSAKeyGenParameterSpec.F4);
    RsaSsaPkcs1PrivateKey originalKey = factory.createKey(format);
    byte[] originalN = originalKey.getPublicKey().getN().toByteArray();
    originalN[0] = (byte) (originalN[0] ^ 0x01);
    ByteString corruptedN = ByteString.copyFrom(originalN);
    RsaSsaPkcs1PublicKey corruptedPub =
        RsaSsaPkcs1PublicKey.newBuilder()
            .setVersion(originalKey.getPublicKey().getVersion())
            .setN(corruptedN)
            .setE(originalKey.getPublicKey().getE())
            .build();

    RsaSsaPkcs1PrivateKey corruptedKey =
        RsaSsaPkcs1PrivateKey.newBuilder()
            .setVersion(originalKey.getVersion())
            .setPublicKey(corruptedPub)
            .setD(originalKey.getD())
            .setP(originalKey.getP())
            .setQ(originalKey.getQ())
            .setDp(originalKey.getDp())
            .setDq(originalKey.getDq())
            .setCrt(originalKey.getCrt())
            .build();
    assertThrows(
        GeneralSecurityException.class,
        () -> manager.getPrimitive(corruptedKey, PublicKeySign.class));
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
}
