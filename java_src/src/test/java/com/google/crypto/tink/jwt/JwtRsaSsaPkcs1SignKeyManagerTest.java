// Copyright 2020 Google LLC
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
package com.google.crypto.tink.jwt;

import static com.google.common.truth.Truth.assertThat;
import static java.nio.charset.StandardCharsets.UTF_8;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThrows;

import com.google.crypto.tink.CleartextKeysetHandle;
import com.google.crypto.tink.KeyTemplate;
import com.google.crypto.tink.KeyTypeManager;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.proto.JwtRsaSsaPkcs1Algorithm;
import com.google.crypto.tink.proto.JwtRsaSsaPkcs1KeyFormat;
import com.google.crypto.tink.proto.JwtRsaSsaPkcs1PrivateKey;
import com.google.crypto.tink.proto.JwtRsaSsaPkcs1PublicKey;
import com.google.crypto.tink.proto.KeyData.KeyMaterialType;
import com.google.crypto.tink.proto.Keyset;
import com.google.crypto.tink.subtle.Base64;
import com.google.crypto.tink.subtle.EngineFactory;
import com.google.crypto.tink.subtle.Enums;
import com.google.crypto.tink.subtle.Random;
import com.google.crypto.tink.subtle.RsaSsaPkcs1SignJce;
import com.google.crypto.tink.testing.TestUtil;
import com.google.gson.JsonObject;
import com.google.protobuf.ByteString;
import com.google.protobuf.ExtensionRegistryLite;
import java.io.ByteArrayInputStream;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.spec.RSAKeyGenParameterSpec;
import java.security.spec.RSAPrivateCrtKeySpec;
import java.util.Set;
import java.util.TreeSet;
import junitparams.JUnitParamsRunner;
import junitparams.Parameters;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;

/** Unit tests for JwtRsaSsaPkcs1SignKeyManager. */
@RunWith(JUnitParamsRunner.class)
public class JwtRsaSsaPkcs1SignKeyManagerTest {
  private final JwtRsaSsaPkcs1SignKeyManager manager = new JwtRsaSsaPkcs1SignKeyManager();
  private final KeyTypeManager.KeyFactory<JwtRsaSsaPkcs1KeyFormat, JwtRsaSsaPkcs1PrivateKey>
      factory = manager.keyFactory();

  @BeforeClass
  public static void setUp() throws Exception {
    JwtSignatureConfig.register();
  }

  private static JwtRsaSsaPkcs1KeyFormat createKeyFormat(
      JwtRsaSsaPkcs1Algorithm algorithm, int modulusSizeInBits, BigInteger publicExponent) {
    return JwtRsaSsaPkcs1KeyFormat.newBuilder()
        .setAlgorithm(algorithm)
        .setModulusSizeInBits(modulusSizeInBits)
        .setPublicExponent(ByteString.copyFrom(publicExponent.toByteArray()))
        .build();
  }

  private static Object[] parametersAlgoAndSize() {
    return new Object[] {
      new Object[] {JwtRsaSsaPkcs1Algorithm.RS256, 2048},
      new Object[] {JwtRsaSsaPkcs1Algorithm.RS256, 3072},
      new Object[] {JwtRsaSsaPkcs1Algorithm.RS256, 4096},
      new Object[] {JwtRsaSsaPkcs1Algorithm.RS384, 2048},
      new Object[] {JwtRsaSsaPkcs1Algorithm.RS384, 3072},
      new Object[] {JwtRsaSsaPkcs1Algorithm.RS384, 4096},
      new Object[] {JwtRsaSsaPkcs1Algorithm.RS512, 2048},
      new Object[] {JwtRsaSsaPkcs1Algorithm.RS512, 3072},
      new Object[] {JwtRsaSsaPkcs1Algorithm.RS512, 4096},
    };
  }

  private static final String algorithmToString(JwtRsaSsaPkcs1Algorithm algo)
      throws GeneralSecurityException {
    switch (algo) {
      case RS256:
        return "RS256";
      case RS384:
        return "RS384";
      case RS512:
        return "RS512";
      default: // fall out
    }
    throw new GeneralSecurityException("unknown algorithm " + algo.name());
  }

  private static Object[] templates() {
    return new Object[] {
      JwtRsaSsaPkcs1SignKeyManager.jwtRs256_2048_F4_Template(),
      JwtRsaSsaPkcs1SignKeyManager.jwtRs256_3072_F4_Template(),
      JwtRsaSsaPkcs1SignKeyManager.jwtRs384_3072_F4_Template(),
      JwtRsaSsaPkcs1SignKeyManager.jwtRs512_4096_F4_Template()
    };
  }

  @Test
  public void basics() throws Exception {
    assertThat(manager.getKeyType())
        .isEqualTo("type.googleapis.com/google.crypto.tink.JwtRsaSsaPkcs1PrivateKey");
    assertThat(manager.getVersion()).isEqualTo(0);
    assertThat(manager.keyMaterialType()).isEqualTo(KeyMaterialType.ASYMMETRIC_PRIVATE);
  }

  @Test
  public void validateKeyFormat_empty_throw() throws Exception {
    assertThrows(
        GeneralSecurityException.class,
        () -> factory.validateKeyFormat(JwtRsaSsaPkcs1KeyFormat.getDefaultInstance()));
  }

  @Test
  @Parameters(method = "parametersAlgoAndSize")
  public void validateKeyFormat_ok(JwtRsaSsaPkcs1Algorithm algorithm, int keySize)
      throws GeneralSecurityException {
    JwtRsaSsaPkcs1KeyFormat format = createKeyFormat(algorithm, keySize, RSAKeyGenParameterSpec.F4);
    factory.validateKeyFormat(format);
  }

  private static Object[] parametersAlgos() {
    return new Object[] {
      JwtRsaSsaPkcs1Algorithm.RS256, JwtRsaSsaPkcs1Algorithm.RS384, JwtRsaSsaPkcs1Algorithm.RS512
    };
  }

  @Test
  @Parameters(method = "parametersAlgos")
  public void invalidKeyFormat_smallKey_throw(JwtRsaSsaPkcs1Algorithm algorithm)
      throws GeneralSecurityException {
    JwtRsaSsaPkcs1KeyFormat format = createKeyFormat(algorithm, 2047, RSAKeyGenParameterSpec.F4);
    assertThrows(GeneralSecurityException.class, () -> factory.validateKeyFormat(format));
  }

  private static Object[] parametersSmallPublicExponents() {
    return new Object[] {
      new Object[] {JwtRsaSsaPkcs1Algorithm.RS256, 3072},
      new Object[] {JwtRsaSsaPkcs1Algorithm.RS256, 4096},
      new Object[] {JwtRsaSsaPkcs1Algorithm.RS384, 2048},
      new Object[] {JwtRsaSsaPkcs1Algorithm.RS384, 3072},
      new Object[] {JwtRsaSsaPkcs1Algorithm.RS384, 4096},
      new Object[] {JwtRsaSsaPkcs1Algorithm.RS512, 2048},
      new Object[] {JwtRsaSsaPkcs1Algorithm.RS512, 3072},
      new Object[] {JwtRsaSsaPkcs1Algorithm.RS512, 4096},
    };
  }

  @Test
  @Parameters(method = "parametersSmallPublicExponents")
  public void invalidKeyFormat_smallPublicExponents_throw(
      JwtRsaSsaPkcs1Algorithm algorithm, int keySize) throws GeneralSecurityException {
    JwtRsaSsaPkcs1KeyFormat format =
        createKeyFormat(algorithm, keySize, RSAKeyGenParameterSpec.F4.subtract(BigInteger.ONE));
    assertThrows(GeneralSecurityException.class, () -> factory.validateKeyFormat(format));
  }

  private static void checkConsistency(
      JwtRsaSsaPkcs1PrivateKey privateKey, JwtRsaSsaPkcs1KeyFormat keyFormat) {
    assertThat(privateKey.getPublicKey().getAlgorithm()).isEqualTo(keyFormat.getAlgorithm());
    assertThat(privateKey.getPublicKey().getE()).isEqualTo(keyFormat.getPublicExponent());
    assertThat(privateKey.getPublicKey().getN().toByteArray().length)
        .isGreaterThan(keyFormat.getModulusSizeInBits() / 8);
  }

  private static void checkKey(JwtRsaSsaPkcs1PrivateKey privateKey) throws Exception {
    JwtRsaSsaPkcs1PublicKey publicKey = privateKey.getPublicKey();
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
  public void createKeys_ok(JwtRsaSsaPkcs1Algorithm algorithm, int keySize) throws Exception {
    if (TestUtil.isTsan()) {
      // factory.createKey is too slow in Tsan.
      return;
    }
    JwtRsaSsaPkcs1KeyFormat format = createKeyFormat(algorithm, keySize, RSAKeyGenParameterSpec.F4);
    JwtRsaSsaPkcs1PrivateKey key = factory.createKey(format);
    checkConsistency(key, format);
    checkKey(key);
  }

  @Test
  @Parameters(method = "parametersAlgoAndSize")
  public void createKey_alwaysNewElement_ok(JwtRsaSsaPkcs1Algorithm algorithm, int keySize)
      throws Exception {
    if (TestUtil.isTsan()) {
      // factory.createKey is too slow in Tsan.
      return;
    }
    JwtRsaSsaPkcs1KeyFormat format = createKeyFormat(algorithm, keySize, RSAKeyGenParameterSpec.F4);
    Set<String> keys = new TreeSet<>();
    // Calls newKey multiple times and make sure that they generate different keys -- takes about a
    // second per key.
    int numTests = 5;
    for (int i = 0; i < numTests; i++) {
      JwtRsaSsaPkcs1PrivateKey key = factory.createKey(format);
      keys.add(TestUtil.hexEncode(key.getQ().toByteArray()));
      keys.add(TestUtil.hexEncode(key.getP().toByteArray()));
    }
    assertThat(keys).hasSize(2 * numTests);
  }

  @Test
  @Parameters(method = "parametersAlgoAndSize")
  public void createCorruptedModulusPrimitive_throws(JwtRsaSsaPkcs1Algorithm algorithm, int keySize)
      throws Exception {
    if (TestUtil.isTsan()) {
      // factory.createKey is too slow in Tsan.
      return;
    }
    JwtRsaSsaPkcs1KeyFormat format = createKeyFormat(algorithm, keySize, RSAKeyGenParameterSpec.F4);
    JwtRsaSsaPkcs1PrivateKey originalKey = factory.createKey(format);
    byte[] originalN = originalKey.getPublicKey().getN().toByteArray();
    originalN[0] = (byte) (originalN[0] ^ 0x01);
    ByteString corruptedN = ByteString.copyFrom(originalN);
    JwtRsaSsaPkcs1PublicKey corruptedPub =
        JwtRsaSsaPkcs1PublicKey.newBuilder()
            .setVersion(originalKey.getPublicKey().getVersion())
            .setN(corruptedN)
            .setE(originalKey.getPublicKey().getE())
            .build();
    JwtRsaSsaPkcs1PrivateKey corruptedKey =
        JwtRsaSsaPkcs1PrivateKey.newBuilder()
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
                JwtRsaSsaPkcs1KeyFormat.getDefaultInstance(),
                new ByteArrayInputStream(Random.randBytes(100))));
  }

  private static void checkTemplate(
      KeyTemplate template, JwtRsaSsaPkcs1Algorithm algorithm, int moduloSize, int publicExponent)
      throws Exception {
    assertThat(template.getTypeUrl()).isEqualTo(new JwtRsaSsaPkcs1SignKeyManager().getKeyType());
    assertThat(template.getOutputPrefixType()).isEqualTo(KeyTemplate.OutputPrefixType.RAW);
    JwtRsaSsaPkcs1KeyFormat format =
        JwtRsaSsaPkcs1KeyFormat.parseFrom(
            template.getValue(), ExtensionRegistryLite.getEmptyRegistry());
    assertThat(format.getAlgorithm()).isEqualTo(algorithm);
    assertThat(format.getModulusSizeInBits()).isEqualTo(moduloSize);
    assertThat(new BigInteger(1, format.getPublicExponent().toByteArray()))
        .isEqualTo(BigInteger.valueOf(publicExponent));
  }

  @Test
  public void testJwtRsa2048AlgoRS256F4Template_ok() throws Exception {
    KeyTemplate template = JwtRsaSsaPkcs1SignKeyManager.jwtRs256_2048_F4_Template();
    checkTemplate(template, JwtRsaSsaPkcs1Algorithm.RS256, 2048, 65537);
  }

  @Test
  public void testJwtRsa4096AlgoRS512F4Template_ok() throws Exception {
    KeyTemplate template = JwtRsaSsaPkcs1SignKeyManager.jwtRs512_4096_F4_Template();
    checkTemplate(template, JwtRsaSsaPkcs1Algorithm.RS512, 4096, 65537);
  }

  @Test
  public void testJwtRsa3072AlgoRS384F4Template_ok() throws Exception {
    KeyTemplate template = JwtRsaSsaPkcs1SignKeyManager.jwtRs384_3072_F4_Template();
    checkTemplate(template, JwtRsaSsaPkcs1Algorithm.RS384, 3072, 65537);
  }

  @Test
  public void testJwtRsa3072AlgoRS256F4Template_ok() throws Exception {
    KeyTemplate template = JwtRsaSsaPkcs1SignKeyManager.jwtRs256_3072_F4_Template();
    checkTemplate(template, JwtRsaSsaPkcs1Algorithm.RS256, 3072, 65537);
  }

  @Test
  public void testJwtRsa4096AlgoRS512F4TemplateWithManager_ok() throws Exception {
    JwtRsaSsaPkcs1KeyFormat format =
        JwtRsaSsaPkcs1KeyFormat.parseFrom(
            JwtRsaSsaPkcs1SignKeyManager.jwtRs512_4096_F4_Template().getValue(),
            ExtensionRegistryLite.getEmptyRegistry());
    new JwtRsaSsaPkcs1SignKeyManager().keyFactory().validateKeyFormat(format);
  }

  @Test
  public void testJwtRsa3072AlgoRS384F4TemplateWithManager_ok() throws Exception {
    JwtRsaSsaPkcs1KeyFormat format =
        JwtRsaSsaPkcs1KeyFormat.parseFrom(
            JwtRsaSsaPkcs1SignKeyManager.jwtRs384_3072_F4_Template().getValue(),
            ExtensionRegistryLite.getEmptyRegistry());
    new JwtRsaSsaPkcs1SignKeyManager().keyFactory().validateKeyFormat(format);
  }

  @Test
  public void testJwtRsa3072AlgoRS256F4TemplateWithManager_ok() throws Exception {
    JwtRsaSsaPkcs1KeyFormat format =
        JwtRsaSsaPkcs1KeyFormat.parseFrom(
            JwtRsaSsaPkcs1SignKeyManager.jwtRs256_3072_F4_Template().getValue(),
            ExtensionRegistryLite.getEmptyRegistry());
    new JwtRsaSsaPkcs1SignKeyManager().keyFactory().validateKeyFormat(format);
  }

  @Test
  @Parameters(method = "templates")
  public void createSignVerify_success(KeyTemplate template) throws Exception {
    if (TestUtil.isTsan()) {
      // KeysetHandle.generateNew is too slow in Tsan.
      return;
    }
    KeysetHandle handle = KeysetHandle.generateNew(template);
    JwtPublicKeySign signer = handle.getPrimitive(JwtPublicKeySign.class);
    JwtPublicKeyVerify verifier =
        handle.getPublicKeysetHandle().getPrimitive(JwtPublicKeyVerify.class);
    RawJwt rawToken = new RawJwt.Builder().setIssuer("issuer").build();
    String signedCompact = signer.signAndEncode(rawToken);
    JwtValidator validator = new JwtValidator.Builder().build();
    VerifiedJwt verifiedToken = verifier.verifyAndDecode(signedCompact, validator);
    assertThat(verifiedToken.getIssuer()).isEqualTo("issuer");
  }

  @Test
  @Parameters(method = "templates")
  public void createSignVerifyDifferentKey_throw(KeyTemplate template) throws Exception {
    if (TestUtil.isTsan()) {
      // KeysetHandle.generateNew is too slow in Tsan.
      return;
    }
    KeysetHandle handle = KeysetHandle.generateNew(template);
    JwtPublicKeySign signer = handle.getPrimitive(JwtPublicKeySign.class);
    RawJwt rawToken = new RawJwt.Builder().setIssuer("issuer").build();
    String signedCompact = signer.signAndEncode(rawToken);

    KeysetHandle otherHandle = KeysetHandle.generateNew(template);
    JwtPublicKeyVerify otherVerifier =
        otherHandle.getPublicKeysetHandle().getPrimitive(JwtPublicKeyVerify.class);
    JwtValidator validator = new JwtValidator.Builder().build();
    assertThrows(
        GeneralSecurityException.class,
        () -> otherVerifier.verifyAndDecode(signedCompact, validator));
  }

  @Test
  @Parameters(method = "templates")
  public void createSignVerify_header_modification_throw(KeyTemplate template) throws Exception {
    if (TestUtil.isTsan()) {
      // KeysetHandle.generateNew is too slow in Tsan.
      return;
    }
    KeysetHandle handle = KeysetHandle.generateNew(template);
    JwtPublicKeySign signer = handle.getPrimitive(JwtPublicKeySign.class);
    JwtPublicKeyVerify verifier =
        handle.getPublicKeysetHandle().getPrimitive(JwtPublicKeyVerify.class);
    RawJwt rawToken = new RawJwt.Builder().setIssuer("issuer").build();
    String signedCompact = signer.signAndEncode(rawToken);

    // Modify the header by adding a space at the end.
    String[] parts = signedCompact.split("\\.", -1);
    String header = new String(Base64.urlSafeDecode(parts[0]), UTF_8);
    String headerBase64 = Base64.urlSafeEncode((header + " ").getBytes(UTF_8));
    String modifiedCompact = headerBase64 + "." + parts[1] + "." + parts[2];

    JwtValidator validator = new JwtValidator.Builder().build();
    assertThrows(
        GeneralSecurityException.class, () -> verifier.verifyAndDecode(modifiedCompact, validator));
  }

  @Test
  @Parameters(method = "templates")
  public void createSignVerify_payload_modification_throw(KeyTemplate template) throws Exception {
    if (TestUtil.isTsan()) {
      // KeysetHandle.generateNew is too slow in Tsan.
      return;
    }
    KeysetHandle handle = KeysetHandle.generateNew(template);
    JwtPublicKeySign signer = handle.getPrimitive(JwtPublicKeySign.class);
    JwtPublicKeyVerify verifier =
        handle.getPublicKeysetHandle().getPrimitive(JwtPublicKeyVerify.class);
    RawJwt rawToken = new RawJwt.Builder().setIssuer("issuer").build();
    String signedCompact = signer.signAndEncode(rawToken);

    // Modify the payload by adding a space at the end.
    String[] parts = signedCompact.split("\\.", -1);
    String payload = new String(Base64.urlSafeDecode(parts[1]), UTF_8);
    String payloadBase64 = Base64.urlSafeEncode((payload + " ").getBytes(UTF_8));
    String modifiedCompact = parts[0] + "." + payloadBase64 + "." + parts[2];

    JwtValidator validator = new JwtValidator.Builder().build();
    assertThrows(
        GeneralSecurityException.class, () -> verifier.verifyAndDecode(modifiedCompact, validator));
  }

  private static final RSAPrivateCrtKey createPrivateKey(JwtRsaSsaPkcs1PrivateKey keyProto)
      throws GeneralSecurityException {
    KeyFactory kf = EngineFactory.KEY_FACTORY.getInstance("RSA");
    return (RSAPrivateCrtKey)
        kf.generatePrivate(
            new RSAPrivateCrtKeySpec(
                new BigInteger(1, keyProto.getPublicKey().getN().toByteArray()),
                new BigInteger(1, keyProto.getPublicKey().getE().toByteArray()),
                new BigInteger(1, keyProto.getD().toByteArray()),
                new BigInteger(1, keyProto.getP().toByteArray()),
                new BigInteger(1, keyProto.getQ().toByteArray()),
                new BigInteger(1, keyProto.getDp().toByteArray()),
                new BigInteger(1, keyProto.getDq().toByteArray()),
                new BigInteger(1, keyProto.getCrt().toByteArray())));
  }

  private static String generateSignedCompact(
      RsaSsaPkcs1SignJce rawSigner, JsonObject header, JsonObject payload)
      throws GeneralSecurityException {
    String payloadBase64 = Base64.urlSafeEncode(payload.toString().getBytes(UTF_8));
    String headerBase64 = Base64.urlSafeEncode(header.toString().getBytes(UTF_8));
    String unsignedCompact = headerBase64 + "." + payloadBase64;
    String signature =
        Base64.urlSafeEncode(rawSigner.sign(unsignedCompact.getBytes(UTF_8)));
    return unsignedCompact + "." + signature;
  }

  @Test
  public void createSignVerify_withDifferentHeaders() throws Exception {
    if (TestUtil.isTsan()) {
      // KeysetHandle.generateNew is too slow in Tsan.
      return;
    }
    KeyTemplate template = JwtRsaSsaPkcs1SignKeyManager.jwtRs256_2048_F4_Template();
    KeysetHandle handle = KeysetHandle.generateNew(template);
    Keyset keyset = CleartextKeysetHandle.getKeyset(handle);
    JwtRsaSsaPkcs1PrivateKey keyProto =
        JwtRsaSsaPkcs1PrivateKey.parseFrom(
            keyset.getKey(0).getKeyData().getValue(), ExtensionRegistryLite.getEmptyRegistry());
    RSAPrivateCrtKey privateKey = createPrivateKey(keyProto);
    JwtRsaSsaPkcs1Algorithm algorithm = keyProto.getPublicKey().getAlgorithm();
    Enums.HashType hash = JwtRsaSsaPkcs1VerifyKeyManager.hashForPkcs1Algorithm(algorithm);
    RsaSsaPkcs1SignJce rawSigner = new RsaSsaPkcs1SignJce(privateKey, hash);
    JwtPublicKeyVerify verifier =
        handle.getPublicKeysetHandle().getPrimitive(JwtPublicKeyVerify.class);
    JwtValidator validator = new JwtValidator.Builder().build();

    JsonObject payload = new JsonObject();
    payload.addProperty(JwtNames.CLAIM_ISSUER, "issuer");

    // valid token, with "typ" set in the header
    JsonObject goodHeader = new JsonObject();
    goodHeader.addProperty(JwtNames.HEADER_ALGORITHM, "RS256");
    goodHeader.addProperty("typ", "JWT");
    String goodSignedCompact = generateSignedCompact(rawSigner, goodHeader, payload);
    verifier.verifyAndDecode(goodSignedCompact, validator);

    // invalid token with an empty header
    JsonObject emptyHeader = new JsonObject();
    String emptyHeaderSignedCompact = generateSignedCompact(rawSigner, emptyHeader, payload);
    assertThrows(
        GeneralSecurityException.class,
        () -> verifier.verifyAndDecode(emptyHeaderSignedCompact, validator));

    // invalid token with an unknown algorithm in the header
    JsonObject badAlgoHeader = new JsonObject();
    badAlgoHeader.addProperty(JwtNames.HEADER_ALGORITHM, "RS255");
    String badAlgoSignedCompact = generateSignedCompact(rawSigner, badAlgoHeader, payload);
    assertThrows(
        GeneralSecurityException.class,
        () -> verifier.verifyAndDecode(badAlgoSignedCompact, validator));

    // token with an unknown "typ" in the header is valid
    JsonObject unknownTypeHeader = new JsonObject();
    unknownTypeHeader.addProperty(JwtNames.HEADER_ALGORITHM, "RS256");
    unknownTypeHeader.addProperty("typ", "unknown");
    String unknownTypeSignedCompact = generateSignedCompact(rawSigner, unknownTypeHeader, payload);
    verifier.verifyAndDecode(unknownTypeSignedCompact, validator);
  }
}
