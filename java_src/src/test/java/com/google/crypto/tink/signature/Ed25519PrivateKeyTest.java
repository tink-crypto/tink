// Copyright 2023 Google LLC
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
import com.google.crypto.tink.internal.KeyTester;
import com.google.crypto.tink.subtle.Hex;
import com.google.crypto.tink.util.Bytes;
import com.google.crypto.tink.util.SecretBytes;
import java.security.GeneralSecurityException;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

@RunWith(JUnit4.class)
public final class Ed25519PrivateKeyTest {
  // Test case from https://www.rfc-editor.org/rfc/rfc8032#page-24
  private static final byte[] SECRET_KEY =
      Hex.decode("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60");
  private static final byte[] PUBLIC_KEY =
      Hex.decode("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a");

  private static final SecretBytes PRIVATE_KEY_BYTES =
      SecretBytes.copyFrom(SECRET_KEY, InsecureSecretKeyAccess.get());
  private static final SecretBytes PUBLIC_KEY_BYTES =
      SecretBytes.copyFrom(PUBLIC_KEY, InsecureSecretKeyAccess.get());

  @Test
  public void createNoPrefixVariantAndGetProperties() throws Exception {
    Ed25519PublicKey publicKey = Ed25519PublicKey.create(PUBLIC_KEY_BYTES);
    Ed25519PrivateKey privateKey = Ed25519PrivateKey.create(publicKey, PRIVATE_KEY_BYTES);

    assertThat(privateKey.getParameters()).isEqualTo(Ed25519Parameters.create());
    assertThat(privateKey.getPrivateKeyBytes()).isEqualTo(PRIVATE_KEY_BYTES);
    assertThat(privateKey.getPublicKey()).isEqualTo(publicKey);
    assertThat(privateKey.getOutputPrefix()).isEqualTo(Bytes.copyFrom(new byte[] {}));
    assertThat(privateKey.getIdRequirementOrNull()).isNull();
  }

  @Test
  public void createTinkVariantAndGetProperties() throws Exception {
    Ed25519PublicKey publicKey =
        Ed25519PublicKey.create(
            Ed25519Parameters.Variant.TINK, PUBLIC_KEY_BYTES, /* idRequirement= */ 0x0708090a);
    Ed25519PrivateKey privateKey = Ed25519PrivateKey.create(publicKey, PRIVATE_KEY_BYTES);

    assertThat(privateKey.getParameters())
        .isEqualTo(Ed25519Parameters.create(Ed25519Parameters.Variant.TINK));
    assertThat(privateKey.getPrivateKeyBytes()).isEqualTo(PRIVATE_KEY_BYTES);
    assertThat(privateKey.getPublicKey()).isEqualTo(publicKey);
    assertThat(privateKey.getOutputPrefix())
        .isEqualTo(Bytes.copyFrom(new byte[] {0x01, 0x07, 0x08, 0x09, 0x0a}));
    assertThat(privateKey.getIdRequirementOrNull()).isEqualTo(0x708090a);
  }

  @Test
  public void createCrunchyVariantAndGetProperties() throws Exception {
    Ed25519PublicKey publicKey =
        Ed25519PublicKey.create(
            Ed25519Parameters.Variant.CRUNCHY, PUBLIC_KEY_BYTES, /* idRequirement= */ 0x0708090a);
    Ed25519PrivateKey privateKey = Ed25519PrivateKey.create(publicKey, PRIVATE_KEY_BYTES);

    assertThat(privateKey.getParameters())
        .isEqualTo(Ed25519Parameters.create(Ed25519Parameters.Variant.CRUNCHY));
    assertThat(privateKey.getPrivateKeyBytes()).isEqualTo(PRIVATE_KEY_BYTES);
    assertThat(privateKey.getPublicKey()).isEqualTo(publicKey);
    assertThat(privateKey.getOutputPrefix())
        .isEqualTo(Bytes.copyFrom(new byte[] {0x00, 0x07, 0x08, 0x09, 0x0a}));
    assertThat(privateKey.getIdRequirementOrNull()).isEqualTo(0x708090a);
  }

  @Test
  public void createLegacyVariantAndGetProperties() throws Exception {
    Ed25519PublicKey publicKey =
        Ed25519PublicKey.create(
            Ed25519Parameters.Variant.LEGACY, PUBLIC_KEY_BYTES, /* idRequirement= */ 0x0708090a);
    Ed25519PrivateKey privateKey = Ed25519PrivateKey.create(publicKey, PRIVATE_KEY_BYTES);

    assertThat(privateKey.getParameters())
        .isEqualTo(Ed25519Parameters.create(Ed25519Parameters.Variant.LEGACY));
    assertThat(privateKey.getPrivateKeyBytes()).isEqualTo(PRIVATE_KEY_BYTES);
    assertThat(privateKey.getPublicKey()).isEqualTo(publicKey);
    assertThat(privateKey.getOutputPrefix())
        .isEqualTo(Bytes.copyFrom(new byte[] {0x00, 0x07, 0x08, 0x09, 0x0a}));
    assertThat(privateKey.getIdRequirementOrNull()).isEqualTo(0x708090a);
  }

  @Test
  public void invalidKeySize() throws Exception {
    SecretBytes invalidSizePrivateKeyBytes = SecretBytes.randomBytes(64);

    Ed25519PublicKey publicKey = Ed25519PublicKey.create(PUBLIC_KEY_BYTES);

    assertThrows(
        GeneralSecurityException.class,
        () -> Ed25519PrivateKey.create(publicKey, invalidSizePrivateKeyBytes));
  }

  @Test
  public void keysMismatch_fails() throws Exception {
    SecretBytes invalidPrivateKeyBytes = SecretBytes.randomBytes(32);

    Ed25519PublicKey publicKey = Ed25519PublicKey.create(PUBLIC_KEY_BYTES);

    assertThrows(
        GeneralSecurityException.class,
        () -> Ed25519PrivateKey.create(publicKey, invalidPrivateKeyBytes));
  }

  @Test
  public void nullPublicKey() throws Exception {
    assertThrows(
        GeneralSecurityException.class, () -> Ed25519PrivateKey.create(null, PRIVATE_KEY_BYTES));
  }

  @Test
  public void testEqualities() throws Exception {
    SecretBytes privateKeyBytesCopy =
        SecretBytes.copyFrom(
            PRIVATE_KEY_BYTES.toByteArray(InsecureSecretKeyAccess.get()),
            InsecureSecretKeyAccess.get());

    Ed25519PublicKey publicKey = Ed25519PublicKey.create(PUBLIC_KEY_BYTES);
    Ed25519PublicKey publicKeyCopy = Ed25519PublicKey.create(PUBLIC_KEY_BYTES);

    // Test case from https://www.rfc-editor.org/rfc/rfc8032#page-24
    SecretBytes publicKeyBytesDiff =
        SecretBytes.copyFrom(
            Hex.decode("3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c"),
            InsecureSecretKeyAccess.get());
    Ed25519PublicKey publicKeyDiff = Ed25519PublicKey.create(publicKeyBytesDiff);
    SecretBytes privateKeyBytesDiff =
        SecretBytes.copyFrom(
            Hex.decode("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb"),
            InsecureSecretKeyAccess.get());

    Ed25519PublicKey publicKeyTink =
        Ed25519PublicKey.create(
            Ed25519Parameters.Variant.TINK, PUBLIC_KEY_BYTES, /* idRequirement= */ 0x0708090a);
    Ed25519PublicKey publicKeyCrunchy =
        Ed25519PublicKey.create(
            Ed25519Parameters.Variant.CRUNCHY, PUBLIC_KEY_BYTES, /* idRequirement= */ 0x0708090a);
    Ed25519PublicKey publicKeyLegacy =
        Ed25519PublicKey.create(
            Ed25519Parameters.Variant.LEGACY, PUBLIC_KEY_BYTES, /* idRequirement= */ 0x0708090a);

    new KeyTester()
        .addEqualityGroup(
            "No prefix, keyBytes",
            Ed25519PrivateKey.create(publicKey, PRIVATE_KEY_BYTES),
            Ed25519PrivateKey.create(publicKey, privateKeyBytesCopy),
            Ed25519PrivateKey.create(publicKeyCopy, PRIVATE_KEY_BYTES))
        .addEqualityGroup(
            "No prefix, different key bytes",
            Ed25519PrivateKey.create(publicKeyDiff, privateKeyBytesDiff))
        .addEqualityGroup(
            "Tink public key, keyBytes", Ed25519PrivateKey.create(publicKeyTink, PRIVATE_KEY_BYTES))
        .addEqualityGroup(
            "Crunchy public key, keyBytes",
            Ed25519PrivateKey.create(publicKeyCrunchy, PRIVATE_KEY_BYTES))
        .addEqualityGroup(
            "Legacy public key, keyBytes",
            Ed25519PrivateKey.create(publicKeyLegacy, PRIVATE_KEY_BYTES))
        .doTests();
  }

  @Test
  public void testDifferentKeyTypesEquality_fails() throws Exception {
    Ed25519PublicKey publicKey = Ed25519PublicKey.create(PUBLIC_KEY_BYTES);
    Ed25519PrivateKey privateKey = Ed25519PrivateKey.create(publicKey, PRIVATE_KEY_BYTES);

    assertThat(privateKey.equalsKey(publicKey)).isFalse();
  }
}
