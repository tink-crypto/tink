// Copyright 2017 Google Inc.
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
import static org.junit.Assert.assertTrue;

import com.google.crypto.tink.InsecureSecretKeyAccess;
import com.google.crypto.tink.KeyTemplate;
import com.google.crypto.tink.KeyTemplates;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.Parameters;
import com.google.crypto.tink.PublicKeySign;
import com.google.crypto.tink.PublicKeyVerify;
import com.google.crypto.tink.internal.KeyTypeManager;
import com.google.crypto.tink.proto.Ed25519KeyFormat;
import com.google.crypto.tink.proto.Ed25519PrivateKey;
import com.google.crypto.tink.proto.Ed25519PublicKey;
import com.google.crypto.tink.proto.KeyData.KeyMaterialType;
import com.google.crypto.tink.signature.internal.testing.Ed25519TestUtil;
import com.google.crypto.tink.signature.internal.testing.SignatureTestVector;
import com.google.crypto.tink.subtle.Ed25519Verify;
import com.google.crypto.tink.subtle.Hex;
import com.google.crypto.tink.subtle.Random;
import com.google.crypto.tink.util.Bytes;
import com.google.crypto.tink.util.SecretBytes;
import com.google.protobuf.ByteString;
import java.io.ByteArrayInputStream;
import java.security.GeneralSecurityException;
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

/** Unit tests for Ed25519PrivateKeyManager. */
@RunWith(Theories.class)
public class Ed25519PrivateKeyManagerTest {
  private final Ed25519PrivateKeyManager manager = new Ed25519PrivateKeyManager();
  private final KeyTypeManager.KeyFactory<Ed25519KeyFormat, Ed25519PrivateKey> factory =
      manager.keyFactory();

  @Before
  public void register() throws Exception {
    SignatureConfig.register();
  }

  @Test
  public void basics() throws Exception {
    assertThat(manager.getKeyType())
        .isEqualTo("type.googleapis.com/google.crypto.tink.Ed25519PrivateKey");
    assertThat(manager.getVersion()).isEqualTo(0);
    assertThat(manager.keyMaterialType()).isEqualTo(KeyMaterialType.ASYMMETRIC_PRIVATE);
  }

  @Test
  public void validateKeyFormat_empty() throws Exception {
    factory.validateKeyFormat(Ed25519KeyFormat.getDefaultInstance());
  }

  @Test
  public void createKey_checkValues() throws Exception {
    Ed25519PrivateKey privateKey = factory.createKey(Ed25519KeyFormat.getDefaultInstance());
    assertThat(privateKey.getVersion()).isEqualTo(0);
    assertThat(privateKey.getPublicKey().getVersion()).isEqualTo(privateKey.getVersion());
    assertThat(privateKey.getKeyValue()).hasSize(32);
    assertThat(privateKey.getPublicKey().getKeyValue()).hasSize(32);
  }

  @Test
  public void validateKey_empty_throws() throws Exception {
    assertThrows(
        GeneralSecurityException.class,
        () -> manager.validateKey(Ed25519PrivateKey.getDefaultInstance()));
  }

  // Tests that generated keys are different.
  @Test
  public void createKey_differentValues() throws Exception {
    Set<String> keys = new TreeSet<>();
    int numTests = 100;
    for (int i = 0; i < numTests; i++) {
      KeysetHandle handle = KeysetHandle.generateNew(Ed25519Parameters.create());
      assertThat(handle.size()).isEqualTo(1);
      assertThat(handle.getAt(0).getKey().getParameters()).isEqualTo(Ed25519Parameters.create());
      com.google.crypto.tink.signature.Ed25519PrivateKey key =
          (com.google.crypto.tink.signature.Ed25519PrivateKey) handle.getAt(0).getKey();
      keys.add(Hex.encode(key.getPrivateKeyBytes().toByteArray(InsecureSecretKeyAccess.get())));
    }
    assertThat(keys).hasSize(numTests);
  }

  @Test
  public void createKeyThenValidate() throws Exception {
    manager.validateKey(factory.createKey(Ed25519KeyFormat.getDefaultInstance()));
  }

  @Test
  public void validateKey_wrongVersion() throws Exception {
    Ed25519PrivateKey validKey = factory.createKey(Ed25519KeyFormat.getDefaultInstance());
    Ed25519PrivateKey invalidKey = Ed25519PrivateKey.newBuilder(validKey).setVersion(1).build();
    assertThrows(GeneralSecurityException.class, () -> manager.validateKey(invalidKey));
  }

  @Test
  public void validateKey_wrongLength64_throws() throws Exception {
    Ed25519PrivateKey validKey = factory.createKey(Ed25519KeyFormat.getDefaultInstance());
    Ed25519PrivateKey invalidKey =
        Ed25519PrivateKey.newBuilder(validKey)
            .setKeyValue(ByteString.copyFrom(Random.randBytes(64)))
            .build();
    assertThrows(GeneralSecurityException.class, () -> manager.validateKey(invalidKey));
  }

  @Test
  public void validateKey_wrongLengthPublicKey64_throws() throws Exception {
    Ed25519PrivateKey validKey = factory.createKey(Ed25519KeyFormat.getDefaultInstance());
    Ed25519PrivateKey invalidKey =
        Ed25519PrivateKey.newBuilder(validKey)
            .setPublicKey(
                Ed25519PublicKey.newBuilder(validKey.getPublicKey())
                    .setKeyValue(ByteString.copyFrom(Random.randBytes(64))))
            .build();
    assertThrows(GeneralSecurityException.class, () -> manager.validateKey(invalidKey));
  }

  /** Tests that a public key is extracted properly from a private key. */
  @Test
  public void getPublicKey_checkValues() throws Exception {
    Ed25519PrivateKey privateKey = factory.createKey(Ed25519KeyFormat.getDefaultInstance());
    Ed25519PublicKey publicKey = manager.getPublicKey(privateKey);
    assertThat(publicKey).isEqualTo(privateKey.getPublicKey());
  }

  @Test
  public void createPrimitive() throws Exception {
    Ed25519PrivateKey privateKey = factory.createKey(Ed25519KeyFormat.getDefaultInstance());
    PublicKeySign signer = manager.getPrimitive(privateKey, PublicKeySign.class);

    PublicKeyVerify verifier =
        new Ed25519Verify(privateKey.getPublicKey().getKeyValue().toByteArray());
    byte[] message = Random.randBytes(135);
    verifier.verify(signer.sign(message), message);
  }

  @Test
  public void testEd25519Template() throws Exception {
    KeyTemplate template = Ed25519PrivateKeyManager.ed25519Template();
    assertThat(template.toParameters())
        .isEqualTo(Ed25519Parameters.create(Ed25519Parameters.Variant.TINK));
  }

  @Test
  public void testRawEd25519Template() throws Exception {
    KeyTemplate template = Ed25519PrivateKeyManager.rawEd25519Template();
    assertThat(template.toParameters())
        .isEqualTo(Ed25519Parameters.create());
  }

  @Test
  public void testKeyTemplateAndManagerCompatibility() throws Exception {
    Parameters p = Ed25519PrivateKeyManager.ed25519Template().toParameters();
    assertThat(KeysetHandle.generateNew(p).getAt(0).getKey().getParameters()).isEqualTo(p);

    p = Ed25519PrivateKeyManager.rawEd25519Template().toParameters();
    assertThat(KeysetHandle.generateNew(p).getAt(0).getKey().getParameters()).isEqualTo(p);
  }

  @DataPoints("templateNames")
  public static final String[] KEY_TEMPLATES =
      new String[] {
        "ED25519", "ED25519_RAW", "ED25519WithRawOutput",
      };

  @Theory
  public void testTemplates(@FromDataPoints("templateNames") String templateName) throws Exception {
    KeysetHandle h = KeysetHandle.generateNew(KeyTemplates.get(templateName));
    assertThat(h.size()).isEqualTo(1);
    assertThat(h.getAt(0).getKey().getParameters())
        .isEqualTo(KeyTemplates.get(templateName).toParameters());
  }

  @Test
  public void testCreateRawKeyFromRandomness() throws Exception {
    byte[] keyMaterial =
        Hex.decode(
            ""
                + "000102030405060708090A0B0C0D0E0F"
                + "101112131415161718191A1B1C1D1E1F"
                + "202122232425262728292A2B2C2D2E2F");
    com.google.crypto.tink.signature.Ed25519PrivateKey key =
        Ed25519PrivateKeyManager.createEd25519KeyFromRandomness(
            Ed25519Parameters.create(Ed25519Parameters.Variant.NO_PREFIX),
            new ByteArrayInputStream(keyMaterial),
            null,
            InsecureSecretKeyAccess.get());
    com.google.crypto.tink.signature.Ed25519PublicKey expectedPublicKey =
        com.google.crypto.tink.signature.Ed25519PublicKey.create(
            Ed25519Parameters.Variant.NO_PREFIX,
            Bytes.copyFrom(
                Hex.decode("03a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8")),
            /* idRequirement= */ null);

    com.google.crypto.tink.signature.Ed25519PrivateKey expectedPrivateKey =
        com.google.crypto.tink.signature.Ed25519PrivateKey.create(
            expectedPublicKey,
            SecretBytes.copyFrom(
                Hex.decode("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F"),
                InsecureSecretKeyAccess.get()));
    assertTrue(key.equalsKey(expectedPrivateKey));
  }

  @Test
  public void testCreateTinkKeyFromRandomness() throws Exception {
    byte[] keyMaterial =
        Hex.decode(
            ""
                + "000102030405060708090A0B0C0D0E0F"
                + "101112131415161718191A1B1C1D1E1F"
                + "202122232425262728292A2B2C2D2E2F");
    com.google.crypto.tink.signature.Ed25519PrivateKey key =
        Ed25519PrivateKeyManager.createEd25519KeyFromRandomness(
            Ed25519Parameters.create(Ed25519Parameters.Variant.TINK),
            new ByteArrayInputStream(keyMaterial),
            2344,
            InsecureSecretKeyAccess.get());
    com.google.crypto.tink.signature.Ed25519PublicKey expectedPublicKey =
        com.google.crypto.tink.signature.Ed25519PublicKey.create(
            Ed25519Parameters.Variant.TINK,
            Bytes.copyFrom(
                Hex.decode("03a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8")),
            2344);

    com.google.crypto.tink.signature.Ed25519PrivateKey expectedPrivateKey =
        com.google.crypto.tink.signature.Ed25519PrivateKey.create(
            expectedPublicKey,
            SecretBytes.copyFrom(
                Hex.decode("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F"),
                InsecureSecretKeyAccess.get()));
    assertTrue(key.equalsKey(expectedPrivateKey));
  }

  @DataPoints("testVectors")
  public static final SignatureTestVector[] ALL_TEST_VECTORS =
      Ed25519TestUtil.createEd25519TestVectors();

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
}
