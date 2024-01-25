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
import com.google.crypto.tink.signature.internal.testing.RsaSsaPssTestUtil;
import com.google.crypto.tink.signature.internal.testing.SignatureTestVector;
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

/** Unit tests for RsaSsaPssSignKeyManager. */
@RunWith(Theories.class)
public class RsaSsaPssSignKeyManagerTest {
  @BeforeClass
  public static void beforeClass() throws Exception {
    RsaSsaPssSignKeyManager.registerPair(/* newKeyAllowed= */ true);
    PublicKeySignWrapper.register();
    PublicKeyVerifyWrapper.register();
  }

  @Test
  public void createSmallKeyUsingParameters_works() throws Exception {
    if (TestUtil.isTsan()) {
      // factory.createKey is too slow in Tsan.
      return;
    }
    RsaSsaPssParameters parameters =
        RsaSsaPssParameters.builder()
            .setModulusSizeBits(3072)
            .setPublicExponent(RsaSsaPssParameters.F4)
            .setSigHashType(RsaSsaPssParameters.HashType.SHA256)
            .setMgf1HashType(RsaSsaPssParameters.HashType.SHA256)
            .setVariant(RsaSsaPssParameters.Variant.NO_PREFIX)
            .setSaltLengthBytes(32)
            .build();
    KeysetHandle handle = KeysetHandle.generateNew(parameters);
    com.google.crypto.tink.Key key = handle.getAt(0).getKey();
    assertThat(key).isInstanceOf(com.google.crypto.tink.signature.RsaSsaPssPrivateKey.class);
    com.google.crypto.tink.signature.RsaSsaPssPrivateKey privateKey =
        (com.google.crypto.tink.signature.RsaSsaPssPrivateKey) key;

    assertThat(privateKey.getPublicKey().getParameters()).isEqualTo(parameters);
    assertThat(privateKey.getPublicKey().getModulus().bitLength()).isEqualTo(3072);
  }


  @Test
  public void createKey_alwaysNewElement() throws Exception {
    if (TestUtil.isTsan()) {
      // factory.createKey is too slow in Tsan.
      return;
    }
    RsaSsaPssParameters parameters =
        RsaSsaPssParameters.builder()
            .setModulusSizeBits(2048)
            .setPublicExponent(RsaSsaPssParameters.F4)
            .setSigHashType(RsaSsaPssParameters.HashType.SHA256)
            .setMgf1HashType(RsaSsaPssParameters.HashType.SHA256)
            .setVariant(RsaSsaPssParameters.Variant.NO_PREFIX)
            .setSaltLengthBytes(32)
            .build();
    Set<BigInteger> primes = new TreeSet<>();
    // Calls newKey multiple times and make sure that they generate different keys -- takes about a
    // second per key.
    int numTests = 5;
    for (int i = 0; i < numTests; i++) {
      KeysetHandle handle = KeysetHandle.generateNew(parameters);
      assertThat(handle.size()).isEqualTo(1);
      com.google.crypto.tink.signature.RsaSsaPssPrivateKey key =
          (com.google.crypto.tink.signature.RsaSsaPssPrivateKey) handle.getAt(0).getKey();
      primes.add(key.getPrimeP().getBigInteger(InsecureSecretKeyAccess.get()));
      primes.add(key.getPrimeQ().getBigInteger(InsecureSecretKeyAccess.get()));
    }
    assertThat(primes).hasSize(2 * numTests);
  }


  @Test
  public void testRsa3072PssSha256F4Template() throws Exception {
    KeyTemplate template = RsaSsaPssSignKeyManager.rsa3072PssSha256F4Template();
    assertThat(template.toParameters())
        .isEqualTo(
            RsaSsaPssParameters.builder()
                .setSigHashType(RsaSsaPssParameters.HashType.SHA256)
                .setMgf1HashType(RsaSsaPssParameters.HashType.SHA256)
                .setSaltLengthBytes(32)
                .setModulusSizeBits(3072)
                .setPublicExponent(RsaSsaPssParameters.F4)
                .setVariant(RsaSsaPssParameters.Variant.TINK)
                .build());
  }

  @Test
  public void testRawRsa3072PssSha256F4Template() throws Exception {
    KeyTemplate template = RsaSsaPssSignKeyManager.rawRsa3072PssSha256F4Template();
    assertThat(template.toParameters())
        .isEqualTo(
            RsaSsaPssParameters.builder()
                .setSigHashType(RsaSsaPssParameters.HashType.SHA256)
                .setMgf1HashType(RsaSsaPssParameters.HashType.SHA256)
                .setSaltLengthBytes(32)
                .setModulusSizeBits(3072)
                .setPublicExponent(RsaSsaPssParameters.F4)
                .setVariant(RsaSsaPssParameters.Variant.NO_PREFIX)
                .build());
  }

  @Test
  public void testRsa4096PssSha512F4Template() throws Exception {
    KeyTemplate template = RsaSsaPssSignKeyManager.rsa4096PssSha512F4Template();
    assertThat(template.toParameters())
        .isEqualTo(
            RsaSsaPssParameters.builder()
                .setSigHashType(RsaSsaPssParameters.HashType.SHA512)
                .setMgf1HashType(RsaSsaPssParameters.HashType.SHA512)
                .setSaltLengthBytes(64)
                .setModulusSizeBits(4096)
                .setPublicExponent(RsaSsaPssParameters.F4)
                .setVariant(RsaSsaPssParameters.Variant.TINK)
                .build());
  }

  @Test
  public void testRawRsa4096PssSha512F4Template() throws Exception {
    KeyTemplate template = RsaSsaPssSignKeyManager.rawRsa4096PssSha512F4Template();
    assertThat(template.toParameters())
        .isEqualTo(
            RsaSsaPssParameters.builder()
                .setSigHashType(RsaSsaPssParameters.HashType.SHA512)
                .setMgf1HashType(RsaSsaPssParameters.HashType.SHA512)
                .setSaltLengthBytes(64)
                .setModulusSizeBits(4096)
                .setPublicExponent(RsaSsaPssParameters.F4)
                .setVariant(RsaSsaPssParameters.Variant.NO_PREFIX)
                .build());
  }

  @Test
  public void testRsa3072PssSha256F4TemplateWithManager() throws Exception {
    if (TestUtil.isTsan()) {
      return; // too slow for tsan
    }
    Parameters p = RsaSsaPssSignKeyManager.rsa3072PssSha256F4Template().toParameters();
    assertThat(KeysetHandle.generateNew(p).getAt(0).getKey().getParameters()).isEqualTo(p);
  }

  @Test
  public void testRawRsa3072PssSha256F4TemplateWithManager() throws Exception {
    if (TestUtil.isTsan()) {
      return; // too slow for tsan
    }
    Parameters p = RsaSsaPssSignKeyManager.rawRsa3072PssSha256F4Template().toParameters();
    assertThat(KeysetHandle.generateNew(p).getAt(0).getKey().getParameters()).isEqualTo(p);
  }

  @Test
  public void testRsa4096PssSha512F4TemplateWithManager() throws Exception {
    if (TestUtil.isTsan()) {
      return; // too slow for tsan
    }
    Parameters p = RsaSsaPssSignKeyManager.rsa4096PssSha512F4Template().toParameters();
    assertThat(KeysetHandle.generateNew(p).getAt(0).getKey().getParameters()).isEqualTo(p);
  }

  @Test
  public void testRawRsa4096PssSha512F4TemplateWithManager() throws Exception {
    if (TestUtil.isTsan()) {
      return; // too slow for tsan
    }
    Parameters p = RsaSsaPssSignKeyManager.rawRsa4096PssSha512F4Template().toParameters();
    assertThat(KeysetHandle.generateNew(p).getAt(0).getKey().getParameters()).isEqualTo(p);
  }

  @DataPoints("templateNames")
  public static final String[] KEY_TEMPLATES =
      new String[] {
        "RSA_SSA_PSS_3072_SHA256_F4",
        "RSA_SSA_PSS_3072_SHA256_F4_RAW",
        "RSA_SSA_PSS_3072_SHA256_SHA256_32_F4",
        "RSA_SSA_PSS_4096_SHA512_F4",
        "RSA_SSA_PSS_4096_SHA512_F4_RAW",
        "RSA_SSA_PSS_4096_SHA512_SHA512_64_F4",
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

  /**
   * Tests that the verifier can verify a the signature for the message and key in the test vector.
   */
  @Theory
  public void test_validateSignatureInTestVector(
      @FromDataPoints("allTests") SignatureTestVector testVector) throws Exception {
    com.google.crypto.tink.signature.RsaSsaPssPrivateKey key =
        (com.google.crypto.tink.signature.RsaSsaPssPrivateKey) testVector.getPrivateKey();
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
   * Tests that the verifier can verify a newly generated signature for the message and key in the
   * test vector.
   */
  @Theory
  public void test_computeAndValidateFreshSignatureWithTestVector(
      @FromDataPoints("allTests") SignatureTestVector testVector) throws Exception {
    com.google.crypto.tink.signature.RsaSsaPssPrivateKey key =
        (com.google.crypto.tink.signature.RsaSsaPssPrivateKey) testVector.getPrivateKey();
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

  @DataPoints("allTests")
  public static final SignatureTestVector[] ALL_TEST_VECTORS =
      RsaSsaPssTestUtil.createRsaPssTestVectors();

  @Test
  public void test_serializeAndParse_works() throws Exception {
    SignatureTestVector testVector = ALL_TEST_VECTORS[0];
    com.google.crypto.tink.signature.RsaSsaPssPrivateKey key =
        (com.google.crypto.tink.signature.RsaSsaPssPrivateKey) testVector.getPrivateKey();
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
                    "type.googleapis.com/google.crypto.tink.RsaSsaPssPrivateKey",
                    PublicKeySign.class))
        .isNotNull();
  }
}
