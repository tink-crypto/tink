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
import static com.google.crypto.tink.internal.TinkBugException.exceptionIsBug;
import static org.junit.Assert.assertThrows;

import com.google.crypto.tink.InsecureSecretKeyAccess;
import com.google.crypto.tink.KeyTemplate;
import com.google.crypto.tink.KeyTemplates;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.Parameters;
import com.google.crypto.tink.PublicKeySign;
import com.google.crypto.tink.PublicKeyVerify;
import com.google.crypto.tink.internal.KeyTypeManager;
import com.google.crypto.tink.proto.EcdsaKeyFormat;
import com.google.crypto.tink.proto.EcdsaParams;
import com.google.crypto.tink.proto.EcdsaPrivateKey;
import com.google.crypto.tink.proto.EcdsaPublicKey;
import com.google.crypto.tink.proto.EcdsaSignatureEncoding;
import com.google.crypto.tink.proto.EllipticCurveType;
import com.google.crypto.tink.proto.HashType;
import com.google.crypto.tink.proto.KeyData.KeyMaterialType;
import com.google.crypto.tink.subtle.Hex;
import com.google.crypto.tink.util.SecretBigInteger;
import com.google.protobuf.ByteString;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.spec.ECPoint;
import java.util.Set;
import java.util.TreeSet;
import javax.annotation.Nullable;
import org.junit.Before;
import org.junit.Test;
import org.junit.experimental.theories.DataPoints;
import org.junit.experimental.theories.FromDataPoints;
import org.junit.experimental.theories.Theories;
import org.junit.experimental.theories.Theory;
import org.junit.runner.RunWith;

/** Unit tests for EcdsaSignKeyManager. */
@RunWith(Theories.class)
public class EcdsaSignKeyManagerTest {
  private final EcdsaSignKeyManager manager = new EcdsaSignKeyManager();
  private final KeyTypeManager.KeyFactory<EcdsaKeyFormat, EcdsaPrivateKey> factory =
      manager.keyFactory();

  @Before
  public void register() throws Exception {
    SignatureConfig.register();
  }

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
    assertThrows(
        GeneralSecurityException.class,
        () -> factory.validateKeyFormat(EcdsaKeyFormat.getDefaultInstance()));
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
    assertThrows(
        GeneralSecurityException.class,
        () ->
            factory.validateKeyFormat(
                createKeyFormat(
                    HashType.SHA1, EllipticCurveType.NIST_P256, EcdsaSignatureEncoding.DER)));
    assertThrows(
        GeneralSecurityException.class,
        () ->
            factory.validateKeyFormat(
                createKeyFormat(
                    HashType.SHA1, EllipticCurveType.NIST_P384, EcdsaSignatureEncoding.DER)));
    assertThrows(
        GeneralSecurityException.class,
        () ->
            factory.validateKeyFormat(
                createKeyFormat(
                    HashType.SHA1, EllipticCurveType.NIST_P521, EcdsaSignatureEncoding.DER)));
  }

  @Test
  public void validateKeyFormat_p384NotWithSha256() throws Exception {
    assertThrows(
        GeneralSecurityException.class,
        () ->
            factory.validateKeyFormat(
                createKeyFormat(
                    HashType.SHA256, EllipticCurveType.NIST_P384, EcdsaSignatureEncoding.DER)));
  }

  @Test
  public void validateKeyFormat_p521OnlyWithSha512() throws Exception {
    assertThrows(
        GeneralSecurityException.class,
        () ->
            factory.validateKeyFormat(
                createKeyFormat(
                    HashType.SHA256, EllipticCurveType.NIST_P521, EcdsaSignatureEncoding.DER)));
    assertThrows(
        GeneralSecurityException.class,
        () ->
            factory.validateKeyFormat(
                createKeyFormat(
                    HashType.SHA384, EllipticCurveType.NIST_P521, EcdsaSignatureEncoding.DER)));
  }

  @Test
  public void validateKeyFormat_unkownsProhibited() throws Exception {
    assertThrows(
        GeneralSecurityException.class,
        () ->
            factory.validateKeyFormat(
                createKeyFormat(
                    HashType.UNKNOWN_HASH,
                    EllipticCurveType.NIST_P256,
                    EcdsaSignatureEncoding.DER)));
    assertThrows(
        GeneralSecurityException.class,
        () ->
            factory.validateKeyFormat(
                createKeyFormat(
                    HashType.SHA256, EllipticCurveType.UNKNOWN_CURVE, EcdsaSignatureEncoding.DER)));
    assertThrows(
        GeneralSecurityException.class,
        () ->
            factory.validateKeyFormat(
                createKeyFormat(
                    HashType.SHA256,
                    EllipticCurveType.NIST_P256,
                    EcdsaSignatureEncoding.UNKNOWN_ENCODING)));
  }

  @Test
  public void validateKey_empty() throws Exception {
    assertThrows(
        GeneralSecurityException.class,
        () -> manager.validateKey(EcdsaPrivateKey.getDefaultInstance()));
  }

  @Test
  public void createCorruptedPublicKeyPrimitive_throws() throws Exception {

    EcdsaKeyFormat format =
        createKeyFormat(HashType.SHA256, EllipticCurveType.NIST_P256, EcdsaSignatureEncoding.DER);
    EcdsaPrivateKey originalKey = factory.createKey(format);
    byte[] originalPubX = originalKey.getPublicKey().getX().toByteArray();
    byte[] originalPubY = originalKey.getPublicKey().getY().toByteArray();
    originalPubX[0] = (byte) (originalPubX[0] ^ 0x01);
    ByteString corruptedPubX = ByteString.copyFrom(originalPubX);
    EcdsaPublicKey corruptedPub =
        EcdsaPublicKey.newBuilder()
            .setVersion(originalKey.getPublicKey().getVersion())
            .setParams(originalKey.getPublicKey().getParams())
            .setX(corruptedPubX)
            .setY(ByteString.copyFrom(originalPubY))
            .build();
    EcdsaPrivateKey corruptedKey =
        EcdsaPrivateKey.newBuilder()
            .setVersion(originalKey.getVersion())
            .setPublicKey(corruptedPub)
            .setKeyValue(originalKey.getKeyValue())
            .build();
    assertThrows(
        GeneralSecurityException.class,
        () -> manager.getPrimitive(corruptedKey, PublicKeySign.class));
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
  public void createKey_nistP256_keySize() throws Exception {
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
  public void createKey_nistP384_keySize() throws Exception {
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
  public void createKey_nistP521_keySize() throws Exception {
    EcdsaPrivateKey privateKey =
        factory.createKey(
            createKeyFormat(
                HashType.SHA512, EllipticCurveType.NIST_P521, EcdsaSignatureEncoding.DER));
    assertThat(privateKey.getKeyValue().size()).isAtLeast(521 / 8 - 8);
    assertThat(privateKey.getKeyValue().size()).isAtMost(521 / 8 + 1);
  }

  @Test
  public void createKey_nistP256_differentValues() throws Exception {
    EcdsaKeyFormat format =
        createKeyFormat(HashType.SHA256, EllipticCurveType.NIST_P256, EcdsaSignatureEncoding.DER);
    Set<String> keys = new TreeSet<>();
    int numTests = 100;
    for (int i = 0; i < numTests; i++) {
      keys.add(Hex.encode(factory.createKey(format).getKeyValue().toByteArray()));
    }
    assertThat(keys).hasSize(numTests);
  }

  @Test
  public void createKey_nistP384_differentValues() throws Exception {
    EcdsaKeyFormat format =
        createKeyFormat(HashType.SHA384, EllipticCurveType.NIST_P384, EcdsaSignatureEncoding.DER);
    Set<String> keys = new TreeSet<>();
    int numTests = 100;
    for (int i = 0; i < numTests; i++) {
      keys.add(Hex.encode(factory.createKey(format).getKeyValue().toByteArray()));
    }
    assertThat(keys).hasSize(numTests);
  }

  @Test
  public void createKey_nistP521_differentValues() throws Exception {
    EcdsaKeyFormat format =
        createKeyFormat(HashType.SHA512, EllipticCurveType.NIST_P521, EcdsaSignatureEncoding.DER);
    Set<String> keys = new TreeSet<>();
    int numTests = 100;
    for (int i = 0; i < numTests; i++) {
      keys.add(Hex.encode(factory.createKey(format).getKeyValue().toByteArray()));
    }
    assertThat(keys).hasSize(numTests);
  }

  @Test
  public void testEcdsaP256Template() throws Exception {
    KeyTemplate template = EcdsaSignKeyManager.ecdsaP256Template();
    assertThat(template.toParameters())
        .isEqualTo(
            EcdsaParameters.builder()
                .setSignatureEncoding(EcdsaParameters.SignatureEncoding.DER)
                .setCurveType(EcdsaParameters.CurveType.NIST_P256)
                .setHashType(EcdsaParameters.HashType.SHA256)
                .setVariant(EcdsaParameters.Variant.TINK)
                .build());
  }

  @Test
  public void testRawEcdsaP256Template() throws Exception {
    KeyTemplate template = EcdsaSignKeyManager.rawEcdsaP256Template();
    assertThat(template.toParameters())
        .isEqualTo(
            EcdsaParameters.builder()
                .setSignatureEncoding(EcdsaParameters.SignatureEncoding.IEEE_P1363)
                .setCurveType(EcdsaParameters.CurveType.NIST_P256)
                .setHashType(EcdsaParameters.HashType.SHA256)
                .setVariant(EcdsaParameters.Variant.NO_PREFIX)
                .build());
  }

  @Test
  public void testKeyTemplateAndManagerCompatibility() throws Exception {
    Parameters p = EcdsaSignKeyManager.ecdsaP256Template().toParameters();
    assertThat(KeysetHandle.generateNew(p).getAt(0).getKey().getParameters()).isEqualTo(p);

    p = EcdsaSignKeyManager.rawEcdsaP256Template().toParameters();
    assertThat(KeysetHandle.generateNew(p).getAt(0).getKey().getParameters()).isEqualTo(p);
  }

  @DataPoints("templateNames")
  public static final String[] KEY_TEMPLATES =
      new String[] {
        "ECDSA_P256",
        "ECDSA_P256_IEEE_P1363",
        "ECDSA_P256_RAW",
        "ECDSA_P256_IEEE_P1363_WITHOUT_PREFIX",
        "ECDSA_P384_SHA384",
        "ECDSA_P384_SHA512",
        "ECDSA_P384_IEEE_P1363",
        "ECDSA_P521",
        "ECDSA_P521_IEEE_P1363",
      };

  @Theory
  public void testTemplates(@FromDataPoints("templateNames") String templateName) throws Exception {
    KeysetHandle h = KeysetHandle.generateNew(KeyTemplates.get(templateName));
    assertThat(h.size()).isEqualTo(1);
    assertThat(h.getAt(0).getKey().getParameters())
        .isEqualTo(KeyTemplates.get(templateName).toParameters());
  }

  @Theory
  public void test_validateSignatureInTestVector(@FromDataPoints("allTests") TestVector testVector)
      throws Exception {
    com.google.crypto.tink.signature.EcdsaPrivateKey key = testVector.privateKey;
    @Nullable Integer id = key.getIdRequirementOrNull();
    if (id == null) {
      id = 12345;
    }
    KeysetHandle handle =
        KeysetHandle.newBuilder()
            .addEntry(KeysetHandle.importKey(key).withFixedId(id).makePrimary())
            .build();
    PublicKeyVerify verifier = handle.getPublicKeysetHandle().getPrimitive(PublicKeyVerify.class);
    verifier.verify(testVector.signature, testVector.message);
  }

  @Theory
  public void test_computeAndValidateFreshSignatureWithTestVector(
      @FromDataPoints("allTests") TestVector testVector) throws Exception {
    com.google.crypto.tink.signature.EcdsaPrivateKey key = testVector.privateKey;
    @Nullable Integer id = key.getIdRequirementOrNull();
    if (id == null) {
      id = 12345;
    }
    KeysetHandle handle =
        KeysetHandle.newBuilder()
            .addEntry(KeysetHandle.importKey(key).withFixedId(id).makePrimary())
            .build();
    PublicKeySign signer = handle.getPrimitive(PublicKeySign.class);
    byte[] signature = signer.sign(testVector.message);
    PublicKeyVerify verifier = handle.getPublicKeysetHandle().getPrimitive(PublicKeyVerify.class);
    verifier.verify(signature, testVector.message);
  }

  private static ECPoint getP256Point() {
    return new ECPoint(
        new BigInteger("60FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB6", 16),
        new BigInteger("7903FE1008B8BC99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C294D4462299", 16));
  }

  private static SecretBigInteger getPrivateP256Value() {
    return SecretBigInteger.fromBigInteger(
        new BigInteger("C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721", 16),
        InsecureSecretKeyAccess.get());
  }

  private static ECPoint getP384Point() {
    return new ECPoint(
        new BigInteger(
            "009d92e0330dfc60ba8b2be32e10f7d2f8457678a112cafd4544b29b7e6addf0249968f54c"
                + "732aa49bc4a38f467edb8424",
            16),
        new BigInteger(
            "0081a3a9c9e878b86755f018a8ec3c5e80921910af919b95f18976e35acc04efa2962e277a"
                + "0b2c990ae92b62d6c75180ba",
            16));
  }

  private static SecretBigInteger getPrivateP384Value() {
    return SecretBigInteger.fromBigInteger(
        new BigInteger(
            "670dc60402d8a4fe52f4e552d2b71f0f81bcf195d8a71a6c7d84efb4f0e4b4a5d0f60a27c9"
                + "4caac46bdeeb79897a3ed9",
            16),
        InsecureSecretKeyAccess.get());
  }

  private static TestVector createTestVector0() throws GeneralSecurityException {
    EcdsaParameters parameters =
        EcdsaParameters.builder()
            .setSignatureEncoding(EcdsaParameters.SignatureEncoding.IEEE_P1363)
            .setCurveType(EcdsaParameters.CurveType.NIST_P256)
            .setHashType(EcdsaParameters.HashType.SHA256)
            .setVariant(EcdsaParameters.Variant.NO_PREFIX)
            .build();
    com.google.crypto.tink.signature.EcdsaPublicKey publicKey =
        com.google.crypto.tink.signature.EcdsaPublicKey.builder()
            .setParameters(parameters)
            .setPublicPoint(getP256Point())
            .build();
    com.google.crypto.tink.signature.EcdsaPrivateKey privateKey =
        com.google.crypto.tink.signature.EcdsaPrivateKey.builder()
            .setPublicKey(publicKey)
            .setPrivateValue(getPrivateP256Value())
            .build();

    return new TestVector(
        privateKey,
        Hex.decode(""),
        Hex.decode(
            "70cbee11e536e9c83d2a2abc6be049117fdab0c420db8191e36f8ce2855262bb5d0b69eefc4dea7b086aa6"
                + "2186e9a7c8600e7b0f1252f704271d5189e7a5cf03"));
  }

  // Signature encoding: DER
  private static TestVector createTestVector1() throws GeneralSecurityException {
    EcdsaParameters parameters =
        EcdsaParameters.builder()
            .setSignatureEncoding(EcdsaParameters.SignatureEncoding.DER)
            .setCurveType(EcdsaParameters.CurveType.NIST_P256)
            .setHashType(EcdsaParameters.HashType.SHA256)
            .setVariant(EcdsaParameters.Variant.NO_PREFIX)
            .build();
    com.google.crypto.tink.signature.EcdsaPublicKey publicKey =
        com.google.crypto.tink.signature.EcdsaPublicKey.builder()
            .setParameters(parameters)
            .setPublicPoint(getP256Point())
            .build();
    com.google.crypto.tink.signature.EcdsaPrivateKey privateKey =
        com.google.crypto.tink.signature.EcdsaPrivateKey.builder()
            .setPublicKey(publicKey)
            .setPrivateValue(getPrivateP256Value())
            .build();

    return new TestVector(
        privateKey,
        Hex.decode(""),
        Hex.decode(
            "3046022100baca7d618e43d44f2754a5368f60b4a41925e2c04d27a672b276ae1f4b3c63a2022100d404a3"
                + "015cb229f7cb036c2b5f77cc546065eed4b75837cec2883d1e35d5eb9f"));
  }

  // Variant: TINK
  private static TestVector createTestVector2() throws GeneralSecurityException {
    EcdsaParameters parameters =
        EcdsaParameters.builder()
            .setSignatureEncoding(EcdsaParameters.SignatureEncoding.IEEE_P1363)
            .setCurveType(EcdsaParameters.CurveType.NIST_P256)
            .setHashType(EcdsaParameters.HashType.SHA256)
            .setVariant(EcdsaParameters.Variant.TINK)
            .build();
    com.google.crypto.tink.signature.EcdsaPublicKey publicKey =
        com.google.crypto.tink.signature.EcdsaPublicKey.builder()
            .setParameters(parameters)
            .setIdRequirement(0x99887766)
            .setPublicPoint(getP256Point())
            .build();
    com.google.crypto.tink.signature.EcdsaPrivateKey privateKey =
        com.google.crypto.tink.signature.EcdsaPrivateKey.builder()
            .setPublicKey(publicKey)
            .setPrivateValue(getPrivateP256Value())
            .build();

    return new TestVector(
        privateKey,
        Hex.decode(""),
        Hex.decode(
            "0199887766"
                + "9b04881165ae47c99c637d306c537bdc97a336ed6f358c7fac1124b3f7166f7d5da6a7b20c61090200276f"
                + "a25ff25e6e39cf56fb5499973b66f25bc1921a1fda"));
  }

  // Variant: CRUNCHY
  private static TestVector createTestVector3() throws GeneralSecurityException {
    EcdsaParameters parameters =
        EcdsaParameters.builder()
            .setSignatureEncoding(EcdsaParameters.SignatureEncoding.IEEE_P1363)
            .setCurveType(EcdsaParameters.CurveType.NIST_P256)
            .setHashType(EcdsaParameters.HashType.SHA256)
            .setVariant(EcdsaParameters.Variant.CRUNCHY)
            .build();
    com.google.crypto.tink.signature.EcdsaPublicKey publicKey =
        com.google.crypto.tink.signature.EcdsaPublicKey.builder()
            .setParameters(parameters)
            .setIdRequirement(0x99887766)
            .setPublicPoint(getP256Point())
            .build();
    com.google.crypto.tink.signature.EcdsaPrivateKey privateKey =
        com.google.crypto.tink.signature.EcdsaPrivateKey.builder()
            .setPublicKey(publicKey)
            .setPrivateValue(getPrivateP256Value())
            .build();

    return new TestVector(
        privateKey,
        Hex.decode(""),
        Hex.decode(
            "0099887766"
                + "9b04881165ae47c99c637d306c537bdc97a336ed6f358c7fac1124b3f7166f7d5da6a7b20c61090200276f"
                + "a25ff25e6e39cf56fb5499973b66f25bc1921a1fda"));
  }

  // Variant: LEGACY
  private static TestVector createTestVector4() throws GeneralSecurityException {
    EcdsaParameters parameters =
        EcdsaParameters.builder()
            .setSignatureEncoding(EcdsaParameters.SignatureEncoding.IEEE_P1363)
            .setCurveType(EcdsaParameters.CurveType.NIST_P256)
            .setHashType(EcdsaParameters.HashType.SHA256)
            .setVariant(EcdsaParameters.Variant.LEGACY)
            .build();
    com.google.crypto.tink.signature.EcdsaPublicKey publicKey =
        com.google.crypto.tink.signature.EcdsaPublicKey.builder()
            .setParameters(parameters)
            .setIdRequirement(0x99887766)
            .setPublicPoint(getP256Point())
            .build();
    com.google.crypto.tink.signature.EcdsaPrivateKey privateKey =
        com.google.crypto.tink.signature.EcdsaPrivateKey.builder()
            .setPublicKey(publicKey)
            .setPrivateValue(getPrivateP256Value())
            .build();

    return new TestVector(
        privateKey,
        Hex.decode(""),
        Hex.decode(
            "0099887766"
                + "515b67e48efb8ebc12e0ce691cf210b18c1e96409667aaedd8d744c64aff843a4e09ebfb9b6c40a6"
                + "540dd0d835693ca08da8c1d8e434770511459088243b0bbb"));
  }

  // Non-empty message
  private static TestVector createTestVector5() throws GeneralSecurityException {
    EcdsaParameters parameters =
        EcdsaParameters.builder()
            .setSignatureEncoding(EcdsaParameters.SignatureEncoding.IEEE_P1363)
            .setCurveType(EcdsaParameters.CurveType.NIST_P256)
            .setHashType(EcdsaParameters.HashType.SHA256)
            .setVariant(EcdsaParameters.Variant.NO_PREFIX)
            .build();
    com.google.crypto.tink.signature.EcdsaPublicKey publicKey =
        com.google.crypto.tink.signature.EcdsaPublicKey.builder()
            .setParameters(parameters)
            .setPublicPoint(getP256Point())
            .build();
    com.google.crypto.tink.signature.EcdsaPrivateKey privateKey =
        com.google.crypto.tink.signature.EcdsaPrivateKey.builder()
            .setPublicKey(publicKey)
            .setPrivateValue(getPrivateP256Value())
            .build();

    return new TestVector(
        privateKey,
        Hex.decode("001122"),
        Hex.decode(
            "bfec68e554a26e161b657efb368a6cd0ec3499c92f2b6240e1b92fa724366a79ca37137274c9125e34c286"
                + "439c848ce3594a3f9450f4108a2fc287a120dfab4f"));
  }

  // NIST_P384
  private static TestVector createTestVector6() throws GeneralSecurityException {
    EcdsaParameters parameters =
        EcdsaParameters.builder()
            .setSignatureEncoding(EcdsaParameters.SignatureEncoding.IEEE_P1363)
            .setCurveType(EcdsaParameters.CurveType.NIST_P384)
            .setHashType(EcdsaParameters.HashType.SHA384)
            .setVariant(EcdsaParameters.Variant.NO_PREFIX)
            .build();
    com.google.crypto.tink.signature.EcdsaPublicKey publicKey =
        com.google.crypto.tink.signature.EcdsaPublicKey.builder()
            .setParameters(parameters)
            .setPublicPoint(getP384Point())
            .build();
    com.google.crypto.tink.signature.EcdsaPrivateKey privateKey =
        com.google.crypto.tink.signature.EcdsaPrivateKey.builder()
            .setPublicKey(publicKey)
            .setPrivateValue(getPrivateP384Value())
            .build();

    return new TestVector(
        privateKey,
        Hex.decode(""),
        Hex.decode(
            "eb19dc251dcbb0aac7634c646b27ccc59a21d6231e08d2b6031ec729ecb0e9927b70bfa66d458b5e1b7186"
                + "355644fa9150602bade9f0c358b9d28263cb427f58bf7d9b892ac75f43ab048360b34ee81653f85e"
                + "c2f10e6e4f0f0e0cafbe91f883"));
  }

  // NIST_P384, SHA512
  private static TestVector createTestVector7() throws GeneralSecurityException {
    EcdsaParameters parameters =
        EcdsaParameters.builder()
            .setSignatureEncoding(EcdsaParameters.SignatureEncoding.IEEE_P1363)
            .setCurveType(EcdsaParameters.CurveType.NIST_P384)
            .setHashType(EcdsaParameters.HashType.SHA512)
            .setVariant(EcdsaParameters.Variant.NO_PREFIX)
            .build();
    com.google.crypto.tink.signature.EcdsaPublicKey publicKey =
        com.google.crypto.tink.signature.EcdsaPublicKey.builder()
            .setParameters(parameters)
            .setPublicPoint(getP384Point())
            .build();
    com.google.crypto.tink.signature.EcdsaPrivateKey privateKey =
        com.google.crypto.tink.signature.EcdsaPrivateKey.builder()
            .setPublicKey(publicKey)
            .setPrivateValue(getPrivateP384Value())
            .build();

    return new TestVector(
        privateKey,
        Hex.decode(""),
        Hex.decode(
            "3db99cec1a865909886f8863ccfa3147f21ccad262a41abc8d964fafa55141a9d89efa6bf0acb4e5ec357c"
                + "6056542e7e016d4a653fde985aad594763900f3f9c4494f45f7a4450422640f57b0ad467950f78dd"
                + "b56641676cb91d392410ed606d"));
  }

  // NIST_P521
  private static TestVector createTestVector8() throws GeneralSecurityException {
    EcdsaParameters parameters =
        EcdsaParameters.builder()
            .setSignatureEncoding(EcdsaParameters.SignatureEncoding.IEEE_P1363)
            .setCurveType(EcdsaParameters.CurveType.NIST_P521)
            .setHashType(EcdsaParameters.HashType.SHA512)
            .setVariant(EcdsaParameters.Variant.NO_PREFIX)
            .build();
    com.google.crypto.tink.signature.EcdsaPublicKey publicKey =
        com.google.crypto.tink.signature.EcdsaPublicKey.builder()
            .setParameters(parameters)
            .setPublicPoint(
                new ECPoint(
                    new BigInteger(
                        "1894550D0785932E00EAA23B694F213F8C3121F86DC97A04E5A7167DB4E5BCD3"
                            + "71123D46E45DB6B5D5370A7F20FB633155D38FFA16D2BD761DCAC474B9A2F502"
                            + "3A4",
                        16),
                    new BigInteger(
                        "0493101C962CD4D2FDDF782285E64584139C2F91B47F87FF82354D6630F746A2"
                            + "8A0DB25741B5B34A828008B22ACC23F924FAAFBD4D33F81EA66956DFEAA2BFDF"
                            + "CF5",
                        16)))
            .build();
    com.google.crypto.tink.signature.EcdsaPrivateKey privateKey =
        com.google.crypto.tink.signature.EcdsaPrivateKey.builder()
            .setPublicKey(publicKey)
            .setPrivateValue(
                SecretBigInteger.fromBigInteger(
                    new BigInteger(
                        "0FAD06DAA62BA3B25D2FB40133DA757205DE67F5BB0018FEE8C86E1B68C7E75C"
                            + "AA896EB32F1F47C70855836A6D16FCC1466F6D8FBEC67DB89EC0C08B0E996B83"
                            + "538",
                        16),
                    InsecureSecretKeyAccess.get()))
            .build();

    return new TestVector(
        privateKey,
        Hex.decode(""),
        Hex.decode(
            "00eaf6672f0696a46046d3b1572814b697c7904fe265fece75e33b90833d08af6513adfb6cbf0a49714426"
                + "33c981d11cd068fcf9431cbe49448b4240a067d860f7fb0168a8d7bf1602050b2255e844aea1df8d"
                + "8ad770053d2c915cca2af6e175c2fb0944f6a9e3262fb9b99910e7fbd6ef4aca887b901ec78678d3"
                + "ec48529c7f06e8c815"));
  }

  @DataPoints("allTests")
  public static final TestVector[] ALL_TEST_VECTORS =
      exceptionIsBug(
          () ->
              new TestVector[] {
                createTestVector0(),
                createTestVector1(),
                createTestVector2(),
                createTestVector3(),
                createTestVector4(),
                createTestVector5(),
                createTestVector6(),
                createTestVector7(),
                createTestVector8(),
              });

  private static class TestVector {
    public final com.google.crypto.tink.signature.EcdsaPrivateKey privateKey;
    public final byte[] message;
    public final byte[] signature;

    public TestVector(
        com.google.crypto.tink.signature.EcdsaPrivateKey privateKey,
        byte[] message,
        byte[] signature) {
      this.privateKey = privateKey;
      this.message = message;
      this.signature = signature;
    }
  }
}
