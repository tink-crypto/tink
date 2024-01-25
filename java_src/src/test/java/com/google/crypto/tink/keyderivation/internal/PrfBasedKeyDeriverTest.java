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

package com.google.crypto.tink.keyderivation.internal;

import static com.google.common.truth.Truth.assertThat;
import static com.google.crypto.tink.internal.TinkBugException.exceptionIsBug;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;

import com.google.crypto.tink.InsecureSecretKeyAccess;
import com.google.crypto.tink.Key;
import com.google.crypto.tink.Parameters;
import com.google.crypto.tink.aead.AesCtrHmacAeadKey;
import com.google.crypto.tink.aead.AesGcmKey;
import com.google.crypto.tink.aead.AesGcmParameters;
import com.google.crypto.tink.aead.AesGcmSivKey;
import com.google.crypto.tink.aead.AesGcmSivParameters;
import com.google.crypto.tink.aead.PredefinedAeadParameters;
import com.google.crypto.tink.aead.XChaCha20Poly1305Key;
import com.google.crypto.tink.aead.XChaCha20Poly1305Parameters;
import com.google.crypto.tink.config.TinkConfig;
import com.google.crypto.tink.daead.AesSivKey;
import com.google.crypto.tink.daead.PredefinedDeterministicAeadParameters;
import com.google.crypto.tink.internal.Util;
import com.google.crypto.tink.jwt.JwtMacConfig;
import com.google.crypto.tink.jwt.JwtSignatureConfig;
import com.google.crypto.tink.keyderivation.KeyDerivationConfig;
import com.google.crypto.tink.keyderivation.PrfBasedKeyDerivationKey;
import com.google.crypto.tink.keyderivation.PrfBasedKeyDerivationParameters;
import com.google.crypto.tink.mac.HmacKey;
import com.google.crypto.tink.mac.PredefinedMacParameters;
import com.google.crypto.tink.prf.HkdfPrfKey;
import com.google.crypto.tink.prf.HkdfPrfParameters;
import com.google.crypto.tink.prf.HmacPrfKey;
import com.google.crypto.tink.prf.PredefinedPrfParameters;
import com.google.crypto.tink.prf.PrfKey;
import com.google.crypto.tink.prf.PrfParameters;
import com.google.crypto.tink.signature.Ed25519Parameters;
import com.google.crypto.tink.signature.Ed25519PrivateKey;
import com.google.crypto.tink.signature.Ed25519PublicKey;
import com.google.crypto.tink.signature.PredefinedSignatureParameters;
import com.google.crypto.tink.streamingaead.AesGcmHkdfStreamingKey;
import com.google.crypto.tink.streamingaead.PredefinedStreamingAeadParameters;
import com.google.crypto.tink.subtle.Hex;
import com.google.crypto.tink.util.Bytes;
import com.google.crypto.tink.util.SecretBytes;
import java.security.GeneralSecurityException;
import java.security.Security;
import javax.annotation.Nullable;
import org.conscrypt.Conscrypt;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.experimental.theories.DataPoints;
import org.junit.experimental.theories.FromDataPoints;
import org.junit.experimental.theories.Theories;
import org.junit.experimental.theories.Theory;
import org.junit.runner.RunWith;

/**
 * Another test class for PrfBasedDeriver. We use a different class because we want to use the
 * Keyset API and do not want to touch the protos. This means that the includes here are the normal
 * classes and not the protos -- which means that all the includes would clash and we would have to
 * extend either the proto or the java AesGcmKey -- for example, if we put it in the same file.
 *
 * <p>Hence we make a different file.
 *
 * <p>The tests here should cover everything, but the previous test also checks some behavior of the
 * internal API (which will be removed). Once the internal API is removed we can remove the other
 * tests as well.
 */
@RunWith(Theories.class)
public final class PrfBasedKeyDeriverTest {

  @BeforeClass
  public static void registerAll() throws Exception {
    if (!Util.isAndroid()) {
      Security.addProvider(Conscrypt.newProvider());
    }
    TinkConfig.register();
    KeyDerivationConfig.register();
    JwtSignatureConfig.register();
    JwtMacConfig.register();
  }

  @Test
  public void basicTest() throws Exception {
    HkdfPrfParameters hkdfPrfParameters =
        HkdfPrfParameters.builder()
            .setKeySizeBytes(32)
            .setHashType(HkdfPrfParameters.HashType.SHA256)
            .build();
    HkdfPrfKey prfKey =
        HkdfPrfKey.builder()
            .setParameters(hkdfPrfParameters)
            .setKeyBytes(
                SecretBytes.copyFrom(
                    Hex.decode("0102030405060708091011121314151617181920212123242526272829303132"),
                    InsecureSecretKeyAccess.get()))
            .build();
    AesGcmParameters derivedKeyParameters =
        AesGcmParameters.builder()
            .setKeySizeBytes(16)
            .setIvSizeBytes(12)
            .setTagSizeBytes(16)
            .setVariant(AesGcmParameters.Variant.NO_PREFIX)
            .build();
    PrfBasedKeyDerivationParameters derivationParameters =
        PrfBasedKeyDerivationParameters.builder()
            .setDerivedKeyParameters(derivedKeyParameters)
            .setPrfParameters(hkdfPrfParameters)
            .build();
    PrfBasedKeyDerivationKey keyDerivationKey =
        PrfBasedKeyDerivationKey.create(derivationParameters, prfKey, /* idRequirement= */ null);

    KeyDeriver deriver = PrfBasedKeyDeriver.create(keyDerivationKey);

    Key derivedKey = deriver.deriveKey(new byte[] {1});
    Key expectedKey =
        AesGcmKey.builder()
            .setParameters(derivedKeyParameters)
            .setKeyBytes(
                SecretBytes.copyFrom(
                    Hex.decode("4A8984211468FF8B78399156F0989A31"), InsecureSecretKeyAccess.get()))
            .build();

    assertThat(derivedKey.getParameters()).isEqualTo(derivedKeyParameters);
    assertThat(derivedKey.equalsKey(expectedKey)).isTrue();
  }

  @Test
  public void create_prfKeyHasNoStreamingPrf_throws() throws Exception {
    PrfParameters prfParameters =
        new PrfParameters() {
          @Override
          public boolean hasIdRequirement() {
            return false;
          }
        };
    // We create an ad-hoc subclass of "PrfKey". For this one, it is not possible that a map
    // (Anonymous subclass) -> StreamingPrf was registered, since the subclass cannot be referenced
    // from anywhere.
    PrfKey prfKey =
        new PrfKey() {
          @Override
          public PrfParameters getParameters() {
            return prfParameters;
          }

          @Override
          public boolean equalsKey(Key key) {
            return key == this;
          }

          @Override
          public Integer getIdRequirementOrNull() {
            return null;
          }
        };
    AesGcmParameters derivedKeyParameters =
        AesGcmParameters.builder()
            .setKeySizeBytes(16)
            .setIvSizeBytes(12)
            .setTagSizeBytes(16)
            .setVariant(AesGcmParameters.Variant.NO_PREFIX)
            .build();
    PrfBasedKeyDerivationParameters derivationParameters =
        PrfBasedKeyDerivationParameters.builder()
            .setDerivedKeyParameters(derivedKeyParameters)
            .setPrfParameters(prfParameters)
            .build();
    PrfBasedKeyDerivationKey keyDerivationKey =
        PrfBasedKeyDerivationKey.create(derivationParameters, prfKey, /* idRequirement= */ null);

    assertThrows(GeneralSecurityException.class, () -> PrfBasedKeyDeriver.create(keyDerivationKey));
  }

  @Test
  public void create_derivedParametersHasNoKeyDerivationFactory_throws() throws Exception {
    HkdfPrfParameters hkdfPrfParameters =
        HkdfPrfParameters.builder()
            .setKeySizeBytes(32)
            .setHashType(HkdfPrfParameters.HashType.SHA256)
            .build();
    HkdfPrfKey prfKey =
        HkdfPrfKey.builder()
            .setParameters(hkdfPrfParameters)
            .setKeyBytes(
                SecretBytes.copyFrom(
                    Hex.decode("0102030405060708091011121314151617181920212123242526272829303132"),
                    InsecureSecretKeyAccess.get()))
            .build();
    Parameters derivedKeyParameters =
        new Parameters() {
          @Override
          public boolean hasIdRequirement() {
            return false;
          }
        };
    PrfBasedKeyDerivationParameters derivationParameters =
        PrfBasedKeyDerivationParameters.builder()
            .setDerivedKeyParameters(derivedKeyParameters)
            .setPrfParameters(hkdfPrfParameters)
            .build();
    PrfBasedKeyDerivationKey keyDerivationKey =
        PrfBasedKeyDerivationKey.create(derivationParameters, prfKey, /* idRequirement= */ null);

    assertThrows(GeneralSecurityException.class, () -> PrfBasedKeyDeriver.create(keyDerivationKey));
  }

  private static final PrfKey FIXED_PRF_KEY =
      exceptionIsBug(
          () ->
              HkdfPrfKey.builder()
                  .setParameters(
                      HkdfPrfParameters.builder()
                          .setKeySizeBytes(32)
                          .setHashType(HkdfPrfParameters.HashType.SHA256)
                          .build())
                  .setKeyBytes(
                      SecretBytes.copyFrom(
                          Hex.decode(
                              "0102030405060708091011121314151617181920212123242526272829303132"),
                          InsecureSecretKeyAccess.get()))
                  .build());

  private static final SecretBytes secretBytesFromHex(String hex) {
    return SecretBytes.copyFrom(Hex.decode(hex), InsecureSecretKeyAccess.get());
  }

  /**
   * A test vector: if we use prfKey in with derivedKeyParameters and salt Hex.decode(inputHex) we
   * get expectedKey.
   *
   * <p>Note that the test vector doesn't specify the derivation key itself. In particular, the
   * idRequirement of the derivationKey is obtained from the expected key (since it should always be
   * the same).
   */
  private static final class TestVector {
    final PrfKey prfKey;
    final Parameters derivedKeyParameters;
    final String inputHex;
    final Key expectedKey;

    TestVector(PrfKey prfKey, Parameters derivedKeyParameters, String inputHex, Key expectedKey) {
      this.prfKey = prfKey;
      this.derivedKeyParameters = derivedKeyParameters;
      this.inputHex = inputHex;
      this.expectedKey = expectedKey;
    }
  }

  // Note: most test vectors use the FIXED_PRF_KEY and "000102" as seed. In this case, the first
  // 64 bytes of the output of the PRF are:
  // 94e397d674deda6e965295698491a3fe b69838a35f1d48143f3c4cbad90eeb24
  // 9c8ddea6d09adc5f89a9a190122b095d 34e166df93b36f417d63baac78115ac3
  private static final TestVector[] createTestVectors() throws Exception {
    return new TestVector[] {
      new TestVector(
          FIXED_PRF_KEY,
          PredefinedAeadParameters.AES128_GCM,
          "",
          AesGcmKey.builder()
              .setParameters(PredefinedAeadParameters.AES128_GCM)
              .setIdRequirement(1234)
              .setKeyBytes(secretBytesFromHex("1b73bdf5293cc533d635f263e35913ec"))
              .build()),
      new TestVector(
          FIXED_PRF_KEY,
          PredefinedAeadParameters.AES128_GCM,
          "000102",
          AesGcmKey.builder()
              .setParameters(PredefinedAeadParameters.AES128_GCM)
              .setIdRequirement(1234)
              .setKeyBytes(secretBytesFromHex("94e397d674deda6e965295698491a3fe"))
              .build()),
      new TestVector(
          FIXED_PRF_KEY,
          PredefinedAeadParameters.AES256_GCM,
          "000102",
          AesGcmKey.builder()
              .setParameters(PredefinedAeadParameters.AES256_GCM)
              .setIdRequirement(1234)
              .setKeyBytes(
                  secretBytesFromHex(
                      "94e397d674deda6e965295698491a3feb69838a35f1d48143f3c4cbad90eeb24"))
              .build()),
      new TestVector(
          FIXED_PRF_KEY,
          PredefinedAeadParameters.AES128_CTR_HMAC_SHA256,
          "000102",
          AesCtrHmacAeadKey.builder()
              .setParameters(PredefinedAeadParameters.AES128_CTR_HMAC_SHA256)
              .setIdRequirement(12345)
              .setAesKeyBytes(secretBytesFromHex("94e397d674deda6e965295698491a3fe"))
              .setHmacKeyBytes(
                  secretBytesFromHex(
                      "b69838a35f1d48143f3c4cbad90eeb249c8ddea6d09adc5f89a9a190122b095d"))
              .build()),
      new TestVector(
          FIXED_PRF_KEY,
          AesGcmSivParameters.builder()
              .setKeySizeBytes(16)
              .setVariant(AesGcmSivParameters.Variant.NO_PREFIX)
              .build(),
          "000102",
          AesGcmSivKey.builder()
              .setParameters(
                  AesGcmSivParameters.builder()
                      .setKeySizeBytes(16)
                      .setVariant(AesGcmSivParameters.Variant.NO_PREFIX)
                      .build())
              .setKeyBytes(secretBytesFromHex("94e397d674deda6e965295698491a3fe"))
              .build()),
      new TestVector(
          FIXED_PRF_KEY,
          XChaCha20Poly1305Parameters.create(XChaCha20Poly1305Parameters.Variant.TINK),
          "000102",
          XChaCha20Poly1305Key.create(
              XChaCha20Poly1305Parameters.Variant.TINK,
              secretBytesFromHex(
                  "94e397d674deda6e965295698491a3feb69838a35f1d48143f3c4cbad90eeb24"),
              1234)),
      new TestVector(
          FIXED_PRF_KEY,
          PredefinedDeterministicAeadParameters.AES256_SIV,
          "000102",
          AesSivKey.builder()
              .setParameters(PredefinedDeterministicAeadParameters.AES256_SIV)
              .setIdRequirement(1234)
              .setKeyBytes(
                  secretBytesFromHex(
                      "94e397d674deda6e965295698491a3feb69838a35f1d48143f3c4cbad90eeb24"
                          + "9c8ddea6d09adc5f89a9a190122b095d34e166df93b36f417d63baac78115ac3"))
              .build()),
      new TestVector(
          FIXED_PRF_KEY,
          PredefinedMacParameters.HMAC_SHA256_256BITTAG,
          "000102",
          HmacKey.builder()
              .setParameters(PredefinedMacParameters.HMAC_SHA256_256BITTAG)
              .setIdRequirement(1234)
              .setKeyBytes(
                  secretBytesFromHex(
                      "94e397d674deda6e965295698491a3feb69838a35f1d48143f3c4cbad90eeb24"))
              .build()),
      new TestVector(
          FIXED_PRF_KEY,
          PredefinedPrfParameters.HMAC_SHA256_PRF,
          "000102",
          HmacPrfKey.builder()
              .setParameters(PredefinedPrfParameters.HMAC_SHA256_PRF)
              .setKeyBytes(
                  secretBytesFromHex(
                      "94e397d674deda6e965295698491a3feb69838a35f1d48143f3c4cbad90eeb24"))
              .build()),
      new TestVector(
          FIXED_PRF_KEY,
          PredefinedSignatureParameters.ED25519,
          "000102",
          Ed25519PrivateKey.create(
              Ed25519PublicKey.create(
                  Ed25519Parameters.Variant.TINK,
                  Bytes.copyFrom(
                      Hex.decode(
                          "c9855bf7fcb4f975e61eac19a530d490f276ddcb1908fcf2ca13329981d58bab")),
                  1234),
              secretBytesFromHex(
                  "94e397d674deda6e965295698491a3feb69838a35f1d48143f3c4cbad90eeb24"))),
      new TestVector(
          FIXED_PRF_KEY,
          Ed25519Parameters.create(Ed25519Parameters.Variant.NO_PREFIX),
          "000102",
          Ed25519PrivateKey.create(
              Ed25519PublicKey.create(
                  Ed25519Parameters.Variant.NO_PREFIX,
                  Bytes.copyFrom(
                      Hex.decode(
                          "c9855bf7fcb4f975e61eac19a530d490f276ddcb1908fcf2ca13329981d58bab")),
                  /* idRequirement= */ null),
              secretBytesFromHex(
                  "94e397d674deda6e965295698491a3feb69838a35f1d48143f3c4cbad90eeb24"))),
      new TestVector(
          FIXED_PRF_KEY,
          PredefinedStreamingAeadParameters.AES256_GCM_HKDF_1MB,
          "000102",
          AesGcmHkdfStreamingKey.create(
              PredefinedStreamingAeadParameters.AES256_GCM_HKDF_1MB,
              secretBytesFromHex(
                  "94e397d674deda6e965295698491a3feb69838a35f1d48143f3c4cbad90eeb24"))),
    };
  }

  @DataPoints("allTests")
  public static final TestVector[] ALL_TEST_VECTORS = exceptionIsBug(() -> createTestVectors());

  @Theory
  public void deriveKeyset_isAsExpected(@FromDataPoints("allTests") TestVector t) throws Exception {
    PrfBasedKeyDerivationParameters derivationParameters =
        PrfBasedKeyDerivationParameters.builder()
            .setDerivedKeyParameters(t.derivedKeyParameters)
            .setPrfParameters(t.prfKey.getParameters())
            .build();

    @Nullable Integer idRequirement = t.expectedKey.getIdRequirementOrNull();
    PrfBasedKeyDerivationKey keyDerivationKey =
        PrfBasedKeyDerivationKey.create(derivationParameters, t.prfKey, idRequirement);
    KeyDeriver deriver = PrfBasedKeyDeriver.create(keyDerivationKey);

    Key derivedKey = deriver.deriveKey(Hex.decode(t.inputHex));

    // The only thing which we need to test is equalsKey(), but we first test other things to make
    // test failures have nicer messages.
    assertThat(derivedKey.getParameters()).isEqualTo(t.derivedKeyParameters);
    assertTrue(derivedKey.equalsKey(t.expectedKey));
  }
}
