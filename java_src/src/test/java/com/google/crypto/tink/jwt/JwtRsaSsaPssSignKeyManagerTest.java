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
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThrows;

import com.google.crypto.tink.KeyTemplate;
import com.google.crypto.tink.KeyTypeManager;
import com.google.crypto.tink.proto.JwtRsaSsaPssAlgorithm;
import com.google.crypto.tink.proto.JwtRsaSsaPssKeyFormat;
import com.google.crypto.tink.proto.JwtRsaSsaPssPrivateKey;
import com.google.crypto.tink.proto.JwtRsaSsaPssPublicKey;
import com.google.crypto.tink.proto.KeyData.KeyMaterialType;
import com.google.crypto.tink.subtle.EngineFactory;
import com.google.crypto.tink.subtle.Random;
import com.google.crypto.tink.testing.TestUtil;
import com.google.protobuf.ByteString;
import com.google.protobuf.ExtensionRegistryLite;
import java.io.ByteArrayInputStream;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.RSAKeyGenParameterSpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.Set;
import java.util.TreeSet;
import junitparams.JUnitParamsRunner;
import junitparams.Parameters;
import org.junit.Test;
import org.junit.runner.RunWith;

/** Unit tests for JwtRsaSsaPssSignKeyManager. */
@RunWith(JUnitParamsRunner.class)
public class JwtRsaSsaPssSignKeyManagerTest {
  private final JwtRsaSsaPssSignKeyManager manager = new JwtRsaSsaPssSignKeyManager();
  private final KeyTypeManager.KeyFactory<JwtRsaSsaPssKeyFormat, JwtRsaSsaPssPrivateKey> factory =
      manager.keyFactory();

  private static JwtRsaSsaPssKeyFormat createKeyFormat(
      JwtRsaSsaPssAlgorithm algorithm, int modulusSizeInBits, BigInteger publicExponent) {
    return JwtRsaSsaPssKeyFormat.newBuilder()
        .setAlgorithm(algorithm)
        .setModulusSizeInBits(modulusSizeInBits)
        .setPublicExponent(ByteString.copyFrom(publicExponent.toByteArray()))
        .build();
  }

  private static Object[] parametersAlgoAndSize() {
    return new Object[] {
      new Object[] {JwtRsaSsaPssAlgorithm.PS256, 2048},
      new Object[] {JwtRsaSsaPssAlgorithm.PS256, 3072},
      new Object[] {JwtRsaSsaPssAlgorithm.PS256, 4096},
      new Object[] {JwtRsaSsaPssAlgorithm.PS384, 2048},
      new Object[] {JwtRsaSsaPssAlgorithm.PS384, 3072},
      new Object[] {JwtRsaSsaPssAlgorithm.PS384, 4096},
      new Object[] {JwtRsaSsaPssAlgorithm.PS512, 2048},
      new Object[] {JwtRsaSsaPssAlgorithm.PS512, 3072},
      new Object[] {JwtRsaSsaPssAlgorithm.PS512, 4096},
    };
  }

  private static final String algorithmToString(JwtRsaSsaPssAlgorithm algo)
      throws GeneralSecurityException {
    switch (algo) {
      case PS256:
        return "PS256";
      case PS384:
        return "PS384";
      case PS512:
        return "PS512";
      default: // fall out
    }
    throw new GeneralSecurityException("unknown algorithm " + algo.name());
  }

  @Test
  public void basics() throws Exception {
    assertThat(manager.getKeyType())
        .isEqualTo("type.googleapis.com/google.crypto.tink.JwtRsaSsaPssPrivateKey");
    assertThat(manager.getVersion()).isEqualTo(0);
    assertThat(manager.keyMaterialType()).isEqualTo(KeyMaterialType.ASYMMETRIC_PRIVATE);
  }

  @Test
  public void validateKeyFormat_empty_throw() throws Exception {
    assertThrows(
        GeneralSecurityException.class,
        () -> factory.validateKeyFormat(JwtRsaSsaPssKeyFormat.getDefaultInstance()));
  }

  @Test
  @Parameters(method = "parametersAlgoAndSize")
  public void validateKeyFormat_ok(JwtRsaSsaPssAlgorithm algorithm, int keySize)
      throws GeneralSecurityException {
    JwtRsaSsaPssKeyFormat format = createKeyFormat(algorithm, keySize, RSAKeyGenParameterSpec.F4);
    factory.validateKeyFormat(format);
  }

  private static Object[] parametersAlgos() {
    return new Object[] {
      JwtRsaSsaPssAlgorithm.PS256, JwtRsaSsaPssAlgorithm.PS384, JwtRsaSsaPssAlgorithm.PS512
    };
  }

  @Test
  @Parameters(method = "parametersAlgos")
  public void invalidKeyFormat_smallKey_throw(JwtRsaSsaPssAlgorithm algorithm)
      throws GeneralSecurityException {
    JwtRsaSsaPssKeyFormat format = createKeyFormat(algorithm, 2047, RSAKeyGenParameterSpec.F4);
    assertThrows(GeneralSecurityException.class, () -> factory.validateKeyFormat(format));
  }

  private static Object[] parametersSmallPublicExponents() {
    return new Object[] {
      new Object[] {JwtRsaSsaPssAlgorithm.PS256, 3072},
      new Object[] {JwtRsaSsaPssAlgorithm.PS256, 4096},
      new Object[] {JwtRsaSsaPssAlgorithm.PS384, 2048},
      new Object[] {JwtRsaSsaPssAlgorithm.PS384, 3072},
      new Object[] {JwtRsaSsaPssAlgorithm.PS384, 4096},
      new Object[] {JwtRsaSsaPssAlgorithm.PS512, 2048},
      new Object[] {JwtRsaSsaPssAlgorithm.PS512, 3072},
      new Object[] {JwtRsaSsaPssAlgorithm.PS512, 4096},
    };
  }

  @Test
  @Parameters(method = "parametersSmallPublicExponents")
  public void invalidKeyFormat_smallPublicExponents_throw(
      JwtRsaSsaPssAlgorithm algorithm, int keySize) throws GeneralSecurityException {
    JwtRsaSsaPssKeyFormat format =
        createKeyFormat(algorithm, keySize, RSAKeyGenParameterSpec.F4.subtract(BigInteger.ONE));
    assertThrows(GeneralSecurityException.class, () -> factory.validateKeyFormat(format));
  }

  private static void checkConsistency(
      JwtRsaSsaPssPrivateKey privateKey, JwtRsaSsaPssKeyFormat keyFormat) {
    assertThat(privateKey.getPublicKey().getAlgorithm()).isEqualTo(keyFormat.getAlgorithm());
    assertThat(privateKey.getPublicKey().getE()).isEqualTo(keyFormat.getPublicExponent());
    assertThat(privateKey.getPublicKey().getN().toByteArray().length)
        .isGreaterThan(keyFormat.getModulusSizeInBits() / 8);
  }

  private static void checkKey(JwtRsaSsaPssPrivateKey privateKey) throws Exception {
    JwtRsaSsaPssPublicKey publicKey = privateKey.getPublicKey();
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
  @Parameters(method = "parametersAlgoAndSize")
  public void createKeys_ok(JwtRsaSsaPssAlgorithm algorithm, int keySize) throws Exception {
    if (TestUtil.isTsan()) {
      // factory.createKey is too slow in Tsan.
      return;
    }
    JwtRsaSsaPssKeyFormat format = createKeyFormat(algorithm, keySize, RSAKeyGenParameterSpec.F4);
    JwtRsaSsaPssPrivateKey key = factory.createKey(format);
    checkConsistency(key, format);
    checkKey(key);
  }

  @Test
  @Parameters(method = "parametersAlgoAndSize")
  public void createKey_alwaysNewElement_ok(JwtRsaSsaPssAlgorithm algorithm, int keySize)
      throws Exception {
    if (TestUtil.isTsan()) {
      // factory.createKey is too slow in Tsan.
      return;
    }
    JwtRsaSsaPssKeyFormat format = createKeyFormat(algorithm, keySize, RSAKeyGenParameterSpec.F4);
    Set<String> keys = new TreeSet<>();
    // Calls newKey multiple times and make sure that they generate different keys -- takes about a
    // second per key.
    int numTests = 5;
    for (int i = 0; i < numTests; i++) {
      JwtRsaSsaPssPrivateKey key = factory.createKey(format);
      keys.add(TestUtil.hexEncode(key.getQ().toByteArray()));
      keys.add(TestUtil.hexEncode(key.getP().toByteArray()));
    }
    assertThat(keys).hasSize(2 * numTests);
  }

  @Test
  @Parameters(method = "parametersAlgoAndSize")
  public void createPrimitive_ok(JwtRsaSsaPssAlgorithm algorithm, int keySize) throws Exception {
    if (TestUtil.isTsan()) {
      // factory.createKey is too slow in Tsan.
      return;
    }
    JwtRsaSsaPssKeyFormat format = createKeyFormat(algorithm, keySize, RSAKeyGenParameterSpec.F4);
    JwtRsaSsaPssPrivateKey key = factory.createKey(format);
    JwtPublicKeySign signer = manager.getPrimitive(key, JwtPublicKeySign.class);
    KeyFactory kf = EngineFactory.KEY_FACTORY.getInstance("RSA");
    BigInteger modulus = new BigInteger(1, key.getPublicKey().getN().toByteArray());
    BigInteger exponent = new BigInteger(1, key.getPublicKey().getE().toByteArray());
    RSAPublicKey publicKey =
        (RSAPublicKey) kf.generatePublic(new RSAPublicKeySpec(modulus, exponent));
    JwtPublicKeyVerify verifier = new JwtRsaSsaPssVerify(publicKey, algorithmToString(algorithm));
    ToBeSignedJwt token = new ToBeSignedJwt.Builder().build();
    JwtValidator validator = new JwtValidator.Builder().build();
    verifier.verify(signer.sign(token), validator);
  }

  @Test
  @Parameters(method = "parametersAlgoAndSize")
  public void createCorruptedModulusPrimitive_throws(JwtRsaSsaPssAlgorithm algorithm, int keySize)
      throws Exception {
    if (TestUtil.isTsan()) {
      // factory.createKey is too slow in Tsan.
      return;
    }
    JwtRsaSsaPssKeyFormat format = createKeyFormat(algorithm, keySize, RSAKeyGenParameterSpec.F4);
    JwtRsaSsaPssPrivateKey originalKey = factory.createKey(format);
    byte[] originalN = originalKey.getPublicKey().getN().toByteArray();
    originalN[0] = (byte) (originalN[0] ^ 0x01);
    ByteString corruptedN = ByteString.copyFrom(originalN);
    JwtRsaSsaPssPublicKey corruptedPub =
        JwtRsaSsaPssPublicKey.newBuilder()
            .setVersion(originalKey.getPublicKey().getVersion())
            .setN(corruptedN)
            .setE(originalKey.getPublicKey().getE())
            .build();

    JwtRsaSsaPssPrivateKey corruptedKey =
        JwtRsaSsaPssPrivateKey.newBuilder()
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
        () -> manager.getPrimitive(corruptedKey, JwtPublicKeySign.class));
  }

  @Test
  public void testDeriveKey_throw() throws Exception {
    assertThrows(
        UnsupportedOperationException.class,
        () ->
            factory.deriveKey(
                JwtRsaSsaPssKeyFormat.getDefaultInstance(),
                new ByteArrayInputStream(Random.randBytes(100))));
  }

  private static void checkTemplate(
      KeyTemplate template, JwtRsaSsaPssAlgorithm algorithm, int moduloSize, int publicExponent)
      throws Exception {
    assertThat(template.getTypeUrl()).isEqualTo(new JwtRsaSsaPssSignKeyManager().getKeyType());
    assertThat(template.getOutputPrefixType()).isEqualTo(KeyTemplate.OutputPrefixType.RAW);
    JwtRsaSsaPssKeyFormat format =
        JwtRsaSsaPssKeyFormat.parseFrom(
            template.getValue(), ExtensionRegistryLite.getEmptyRegistry());
    assertThat(format.getAlgorithm()).isEqualTo(algorithm);
    assertThat(format.getModulusSizeInBits()).isEqualTo(moduloSize);
    assertThat(new BigInteger(1, format.getPublicExponent().toByteArray()))
        .isEqualTo(BigInteger.valueOf(publicExponent));
  }

  @Test
  public void testJwtRsa2048AlgoRS256F4Template_ok() throws Exception {
    KeyTemplate template = JwtRsaSsaPssSignKeyManager.jwtRsa2048AlgoPS256F4Template();
    checkTemplate(template, JwtRsaSsaPssAlgorithm.PS256, 2048, 65537);
  }

  @Test
  public void testJwtRsa4096AlgoRS512F4Template_ok() throws Exception {
    KeyTemplate template = JwtRsaSsaPssSignKeyManager.jwtRsa4096AlgoPS512F4Template();
    checkTemplate(template, JwtRsaSsaPssAlgorithm.PS512, 4096, 65537);
  }

  @Test
  public void testJwtRsa3072AlgoRS384F4Template_ok() throws Exception {
    KeyTemplate template = JwtRsaSsaPssSignKeyManager.jwtRsa3072AlgoPS384F4Template();
    checkTemplate(template, JwtRsaSsaPssAlgorithm.PS384, 3072, 65537);
  }

  @Test
  public void testJwtRsa3072AlgoRS256F4Template_ok() throws Exception {
    KeyTemplate template = JwtRsaSsaPssSignKeyManager.jwtRsa3072AlgoPS256F4Template();
    checkTemplate(template, JwtRsaSsaPssAlgorithm.PS256, 3072, 65537);
  }

  @Test
  public void testJwtRsa4096AlgoPS512F4TemplateWithManager_ok() throws Exception {
    JwtRsaSsaPssKeyFormat format =
        JwtRsaSsaPssKeyFormat.parseFrom(
            JwtRsaSsaPssSignKeyManager.jwtRsa4096AlgoPS512F4Template().getValue(),
            ExtensionRegistryLite.getEmptyRegistry());
    new JwtRsaSsaPssSignKeyManager().keyFactory().validateKeyFormat(format);
  }

  @Test
  public void testJwtRsa3072AlgoPS384F4TemplateWithManager_ok() throws Exception {
    JwtRsaSsaPssKeyFormat format =
        JwtRsaSsaPssKeyFormat.parseFrom(
            JwtRsaSsaPssSignKeyManager.jwtRsa3072AlgoPS384F4Template().getValue(),
            ExtensionRegistryLite.getEmptyRegistry());
    new JwtRsaSsaPssSignKeyManager().keyFactory().validateKeyFormat(format);
  }

  @Test
  public void testJwtRsa3072AlgoPS256F4TemplateWithManager_ok() throws Exception {
    JwtRsaSsaPssKeyFormat format =
        JwtRsaSsaPssKeyFormat.parseFrom(
            JwtRsaSsaPssSignKeyManager.jwtRsa3072AlgoPS256F4Template().getValue(),
            ExtensionRegistryLite.getEmptyRegistry());
    new JwtRsaSsaPssSignKeyManager().keyFactory().validateKeyFormat(format);
  }
}
