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
import static com.google.crypto.tink.testing.KeyTypeManagerTestUtil.testKeyTemplateCompatible;
import static org.junit.Assert.assertThrows;

import com.google.crypto.tink.KeyTemplate;
import com.google.crypto.tink.KeyTypeManager;
import com.google.crypto.tink.PublicKeySign;
import com.google.crypto.tink.proto.EcdsaKeyFormat;
import com.google.crypto.tink.proto.EcdsaParams;
import com.google.crypto.tink.proto.EcdsaPrivateKey;
import com.google.crypto.tink.proto.EcdsaPublicKey;
import com.google.crypto.tink.proto.EcdsaSignatureEncoding;
import com.google.crypto.tink.proto.EllipticCurveType;
import com.google.crypto.tink.proto.HashType;
import com.google.crypto.tink.proto.KeyData.KeyMaterialType;
import com.google.crypto.tink.testing.TestUtil;
import com.google.protobuf.ByteString;
import com.google.protobuf.ExtensionRegistryLite;
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
  private final KeyTypeManager.KeyFactory<EcdsaKeyFormat, EcdsaPrivateKey> factory =
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
      keys.add(TestUtil.hexEncode(factory.createKey(format).getKeyValue().toByteArray()));
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
      keys.add(TestUtil.hexEncode(factory.createKey(format).getKeyValue().toByteArray()));
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
      keys.add(TestUtil.hexEncode(factory.createKey(format).getKeyValue().toByteArray()));
    }
    assertThat(keys).hasSize(numTests);
  }

  @Test
  public void testEcdsaP256Template() throws Exception {
    KeyTemplate template = EcdsaSignKeyManager.ecdsaP256Template();
    assertThat(template.getTypeUrl()).isEqualTo(new EcdsaSignKeyManager().getKeyType());
    assertThat(template.getOutputPrefixType()).isEqualTo(KeyTemplate.OutputPrefixType.TINK);
    EcdsaKeyFormat format =
        EcdsaKeyFormat.parseFrom(template.getValue(), ExtensionRegistryLite.getEmptyRegistry());

    assertThat(format.hasParams()).isTrue();
    assertThat(format.getParams().getHashType()).isEqualTo(HashType.SHA256);
    assertThat(format.getParams().getCurve()).isEqualTo(EllipticCurveType.NIST_P256);
    assertThat(format.getParams().getEncoding()).isEqualTo(EcdsaSignatureEncoding.DER);
  }

  @Test
  public void testRawEcdsaP256Template() throws Exception {
    KeyTemplate template = EcdsaSignKeyManager.rawEcdsaP256Template();
    assertThat(template.getTypeUrl()).isEqualTo(new EcdsaSignKeyManager().getKeyType());
    assertThat(template.getOutputPrefixType()).isEqualTo(KeyTemplate.OutputPrefixType.RAW);
    EcdsaKeyFormat format =
        EcdsaKeyFormat.parseFrom(template.getValue(), ExtensionRegistryLite.getEmptyRegistry());

    assertThat(format.hasParams()).isTrue();
    assertThat(format.getParams().getHashType()).isEqualTo(HashType.SHA256);
    assertThat(format.getParams().getCurve()).isEqualTo(EllipticCurveType.NIST_P256);
    assertThat(format.getParams().getEncoding()).isEqualTo(EcdsaSignatureEncoding.IEEE_P1363);
  }

  @Test
  public void testKeyTemplateAndManagerCompatibility() throws Exception {
    EcdsaSignKeyManager manager = new EcdsaSignKeyManager();

    testKeyTemplateCompatible(manager, EcdsaSignKeyManager.ecdsaP256Template());
    testKeyTemplateCompatible(manager, EcdsaSignKeyManager.rawEcdsaP256Template());
  }

  @Test
  public void testKeyFormats() throws Exception {
    factory.validateKeyFormat(factory.keyFormats().get("ECDSA_P256").keyFormat);
    factory.validateKeyFormat(factory.keyFormats().get("ECDSA_P256_IEEE_P1363").keyFormat);
    factory.validateKeyFormat(factory.keyFormats().get("ECDSA_P256_RAW").keyFormat);
    factory.validateKeyFormat(
        factory.keyFormats().get("ECDSA_P256_IEEE_P1363_WITHOUT_PREFIX").keyFormat);

    factory.validateKeyFormat(factory.keyFormats().get("ECDSA_P384").keyFormat);
    factory.validateKeyFormat(factory.keyFormats().get("ECDSA_P384_IEEE_P1363").keyFormat);

    factory.validateKeyFormat(factory.keyFormats().get("ECDSA_P521").keyFormat);
    factory.validateKeyFormat(factory.keyFormats().get("ECDSA_P521_IEEE_P1363").keyFormat);
  }
}
