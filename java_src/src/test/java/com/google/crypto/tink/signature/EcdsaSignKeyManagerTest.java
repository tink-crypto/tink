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
import static org.junit.Assert.assertThrows;

import com.google.crypto.tink.InsecureSecretKeyAccess;
import com.google.crypto.tink.KeyTemplate;
import com.google.crypto.tink.KeyTemplates;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.Parameters;
import com.google.crypto.tink.PublicKeySign;
import com.google.crypto.tink.PublicKeyVerify;
import com.google.crypto.tink.internal.KeyManagerRegistry;
import com.google.crypto.tink.internal.Util;
import com.google.crypto.tink.signature.internal.testing.EcdsaTestUtil;
import com.google.crypto.tink.signature.internal.testing.SignatureTestVector;
import com.google.crypto.tink.testing.TestUtil;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.util.Arrays;
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
  @Before
  public void register() throws Exception {
    SignatureConfig.register();
  }

  @Test
  public void testKeyManagersRegistered() throws Exception {
    assertThat(
            KeyManagerRegistry.globalInstance()
                .getKeyManager(
                    "type.googleapis.com/google.crypto.tink.EcdsaPrivateKey", PublicKeySign.class))
        .isNotNull();
    assertThat(
            KeyManagerRegistry.globalInstance()
                .getKeyManager(
                    "type.googleapis.com/google.crypto.tink.EcdsaPublicKey", PublicKeyVerify.class))
        .isNotNull();
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
  public void callingCreateTwiceGivesDifferentKeys() throws Exception {
    int numKeys = 2;
    if (TestUtil.isAndroid() || TestUtil.isTsan()) {
      numKeys = 2;
    }
    Parameters p = EcdsaSignKeyManager.ecdsaP256Template().toParameters();
    Set<BigInteger> keys = new TreeSet<>();
    for (int i = 0; i < numKeys; ++i) {
      EcdsaPrivateKey key = (EcdsaPrivateKey) KeysetHandle.generateNew(p).getAt(0).getKey();
      keys.add(key.getPrivateValue().getBigInteger(InsecureSecretKeyAccess.get()));
    }
    assertThat(keys).hasSize(numKeys);
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
    @Nullable Integer apiLevel = Util.getAndroidApiLevel();
    if (apiLevel != null && apiLevel == 19) {
      // Android API 19 is slower than the others in this.
      return;
    }
    KeysetHandle h = KeysetHandle.generateNew(KeyTemplates.get(templateName));
    assertThat(h.size()).isEqualTo(1);
    assertThat(h.getAt(0).getKey().getParameters())
        .isEqualTo(KeyTemplates.get(templateName).toParameters());
  }

  /**
   * Tests that when using the normal public API of Tink, signatures in the test vector can be
   * verified.
   */
  @Theory
  public void test_validateSignatureInTestVector(
      @FromDataPoints("allTests") SignatureTestVector testVector) throws Exception {
    @Nullable Integer apiLevel = Util.getAndroidApiLevel();
    if (apiLevel != null && apiLevel == 19) {
      // Android API 19 is slower than the others in this.
      return;
    }
    SignaturePrivateKey key = testVector.getPrivateKey();
    KeysetHandle.Builder.Entry entry = KeysetHandle.importKey(key).makePrimary();
    @Nullable Integer id = key.getIdRequirementOrNull();
    if (id == null) {
      entry.withRandomId();
    } else {
      entry.withFixedId(id);
    }
    KeysetHandle handle = KeysetHandle.newBuilder().addEntry(entry).build();
    PublicKeyVerify verifier = handle.getPublicKeysetHandle().getPrimitive(PublicKeyVerify.class);
    verifier.verify(testVector.getSignature(), testVector.getMessage());
  }

  /**
   * Tests that when using the normal public API of Tink, newly created signatures can be verified.
   */
  @Theory
  public void test_computeAndValidateFreshSignatureWithTestVector(
      @FromDataPoints("allTests") SignatureTestVector testVector) throws Exception {
    @Nullable Integer apiLevel = Util.getAndroidApiLevel();
    if (apiLevel != null && apiLevel == 19) {
      // Android API 19 is slower than the others in this.
      return;
    }
    SignaturePrivateKey key = testVector.getPrivateKey();
    KeysetHandle.Builder.Entry entry = KeysetHandle.importKey(key).makePrimary();
    @Nullable Integer id = key.getIdRequirementOrNull();
    if (id == null) {
      entry.withRandomId();
    } else {
      entry.withFixedId(id);
    }
    KeysetHandle handle = KeysetHandle.newBuilder().addEntry(entry).build();
    PublicKeySign signer = handle.getPrimitive(PublicKeySign.class);
    byte[] signature = signer.sign(testVector.getMessage());
    PublicKeyVerify verifier = handle.getPublicKeysetHandle().getPrimitive(PublicKeyVerify.class);
    verifier.verify(signature, testVector.getMessage());
  }

  private static byte[] modifyInput(byte[] message) {
    if (message.length == 0) {
      return new byte[] {1};
    }
    byte[] copy = Arrays.copyOf(message, message.length);
    copy[0] ^= 1;
    return copy;
  }

  @Theory
  public void test_computeFreshSignatureWithTestVector_throwsWithWrongMessage(
      @FromDataPoints("allTests") SignatureTestVector testVector) throws Exception {
    @Nullable Integer apiLevel = Util.getAndroidApiLevel();
    if (apiLevel != null && apiLevel == 19) {
      // Android API 19 is slower than the others in this.
      return;
    }
    SignaturePrivateKey key = testVector.getPrivateKey();
    KeysetHandle.Builder.Entry entry = KeysetHandle.importKey(key).makePrimary();
    @Nullable Integer id = key.getIdRequirementOrNull();
    if (id == null) {
      entry.withRandomId();
    } else {
      entry.withFixedId(id);
    }
    KeysetHandle handle = KeysetHandle.newBuilder().addEntry(entry).build();
    PublicKeySign signer = handle.getPrimitive(PublicKeySign.class);
    byte[] signature = signer.sign(testVector.getMessage());
    PublicKeyVerify verifier = handle.getPublicKeysetHandle().getPrimitive(PublicKeyVerify.class);
    assertThrows(
        GeneralSecurityException.class,
        () -> verifier.verify(signature, modifyInput(testVector.getMessage())));
  }

  @DataPoints("allTests")
  public static final SignatureTestVector[] ALL_TEST_VECTORS =
      EcdsaTestUtil.createEcdsaTestVectors();
}
