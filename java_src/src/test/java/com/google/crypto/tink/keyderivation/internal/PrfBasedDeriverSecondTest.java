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
import static com.google.common.truth.Truth.assertWithMessage;
import static com.google.crypto.tink.internal.TinkBugException.exceptionIsBug;

import com.google.crypto.tink.InsecureSecretKeyAccess;
import com.google.crypto.tink.Key;
import com.google.crypto.tink.KeyStatus;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.Parameters;
import com.google.crypto.tink.TinkProtoKeysetFormat;
import com.google.crypto.tink.aead.AesGcmKey;
import com.google.crypto.tink.aead.AesGcmParameters;
import com.google.crypto.tink.aead.AesGcmSivParameters;
import com.google.crypto.tink.aead.PredefinedAeadParameters;
import com.google.crypto.tink.aead.XChaCha20Poly1305Parameters;
import com.google.crypto.tink.config.TinkConfig;
import com.google.crypto.tink.daead.PredefinedDeterministicAeadParameters;
import com.google.crypto.tink.internal.Util;
import com.google.crypto.tink.jwt.JwtMacConfig;
import com.google.crypto.tink.jwt.JwtSignatureConfig;
import com.google.crypto.tink.keyderivation.KeyDerivationConfig;
import com.google.crypto.tink.keyderivation.KeysetDeriver;
import com.google.crypto.tink.keyderivation.PrfBasedKeyDerivationKey;
import com.google.crypto.tink.keyderivation.PrfBasedKeyDerivationParameters;
import com.google.crypto.tink.mac.PredefinedMacParameters;
import com.google.crypto.tink.prf.HkdfPrfKey;
import com.google.crypto.tink.prf.HkdfPrfParameters;
import com.google.crypto.tink.prf.PredefinedPrfParameters;
import com.google.crypto.tink.prf.PrfKey;
import com.google.crypto.tink.signature.PredefinedSignatureParameters;
import com.google.crypto.tink.streamingaead.PredefinedStreamingAeadParameters;
import com.google.crypto.tink.subtle.Hex;
import com.google.crypto.tink.util.SecretBytes;
import java.security.Security;
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
public final class PrfBasedDeriverSecondTest {

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

    KeysetHandle keyset =
        KeysetHandle.newBuilder()
            .addEntry(KeysetHandle.importKey(keyDerivationKey).withFixedId(123).makePrimary())
            .build();

    KeysetDeriver deriver = keyset.getPrimitive(KeysetDeriver.class);

    KeysetHandle derivedKeyset = deriver.deriveKeyset(new byte[] {1});
    Key expectedKey =
        AesGcmKey.builder()
            .setParameters(derivedKeyParameters)
            .setKeyBytes(
                SecretBytes.copyFrom(
                    Hex.decode("4A8984211468FF8B78399156F0989A31"), InsecureSecretKeyAccess.get()))
            .build();

    assertThat(derivedKeyset.size()).isEqualTo(1);
    assertThat(derivedKeyset.getAt(0).getId()).isEqualTo(123);
    assertThat(derivedKeyset.getAt(0).getStatus()).isEqualTo(KeyStatus.ENABLED);
    assertThat(derivedKeyset.getAt(0).getKey().getParameters()).isEqualTo(derivedKeyParameters);
    assertThat(derivedKeyset.getAt(0).getKey().equalsKey(expectedKey)).isTrue();
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

  private static final class TestVector {
    final Parameters derivedKeyParameters;
    final String inputHex;
    final String resultingKeysetHex;

    TestVector(Parameters derivedKeyParameters, String inputHex, String resultingKeysetHex) {
      this.derivedKeyParameters = derivedKeyParameters;
      this.inputHex = inputHex;
      this.resultingKeysetHex = resultingKeysetHex;
    }
  }

  private static final TestVector[] createTestVectors() throws Exception {
    return new TestVector[] {
      new TestVector(
          PredefinedAeadParameters.AES128_GCM,
          "",
          "08c26012510a480a30747970652e676f6f676c65617069732e636f6d2f676f6f676c652e63727970746f2e74"
              + "696e6b2e41657347636d4b657912121a101b73bdf5293cc533d635f263e35913ec1801100118c26020"
              + "01"),
      new TestVector(
          PredefinedAeadParameters.AES128_GCM,
          "01",
          "08c26012510a480a30747970652e676f6f676c65617069732e636f6d2f676f6f676c652e63727970746f2e74"
              + "696e6b2e41657347636d4b657912121a104a8984211468ff8b78399156f0989a311801100118c26020"
              + "01"),
      new TestVector(
          PredefinedAeadParameters.AES256_GCM,
          "000102",
          "08c26012610a580a30747970652e676f6f676c65617069732e636f6d2f676f6f676c652e63727970746f2e74"
              + "696e6b2e41657347636d4b657912221a2094e397d674deda6e965295698491a3feb69838a35f1d4814"
              + "3f3c4cbad90eeb241801100118c2602001"),
      new TestVector(
          PredefinedAeadParameters.AES128_CTR_HMAC_SHA256,
          "000102",
          "08c260128a010a80010a38747970652e676f6f676c65617069732e636f6d2f676f6f676c652e63727970746f"
              + "2e74696e6b2e416573437472486d6163416561644b657912421216120208101a1094e397d674deda6e"
              + "965295698491a3fe1a281204080310101a20b69838a35f1d48143f3c4cbad90eeb249c8ddea6d09adc"
              + "5f89a9a190122b095d1801100118c2602001"),
      new TestVector(
          AesGcmSivParameters.builder()
              .setKeySizeBytes(16)
              .setVariant(AesGcmSivParameters.Variant.NO_PREFIX)
              .build(),
          "000102",
          "08c26012540a4b0a33747970652e676f6f676c65617069732e636f6d2f676f6f676c652e63727970746f2e74"
              + "696e6b2e41657347636d5369764b657912121a1094e397d674deda6e965295698491a3fe1801100118"
              + "c2602003"),
      new TestVector(
          XChaCha20Poly1305Parameters.create(),
          "000102",
          "08c260126c0a630a3b747970652e676f6f676c65617069732e636f6d2f676f6f676c652e63727970746f2e74"
              + "696e6b2e584368614368613230506f6c79313330354b657912221a2094e397d674deda6e9652956984"
              + "91a3feb69838a35f1d48143f3c4cbad90eeb241801100118c2602003"),
      new TestVector(
          PredefinedDeterministicAeadParameters.AES256_SIV,
          "000102",
          "08c2601281010a780a30747970652e676f6f676c65617069732e636f6d2f676f6f676c652e63727970746f2e"
              + "74696e6b2e4165735369764b65791242124094e397d674deda6e965295698491a3feb69838a35f1d48"
              + "143f3c4cbad90eeb249c8ddea6d09adc5f89a9a190122b095d34e166df93b36f417d63baac78115ac3"
              + "1801100118c2602001"),
      new TestVector(
          PredefinedMacParameters.HMAC_SHA256_256BITTAG,
          "000102",
          "08c26012650a5c0a2e747970652e676f6f676c65617069732e636f6d2f676f6f676c652e63727970746f2e74"
              + "696e6b2e486d61634b657912281204080310201a2094e397d674deda6e965295698491a3feb69838a3"
              + "5f1d48143f3c4cbad90eeb241801100118c2602001"),
      new TestVector(
          PredefinedPrfParameters.HMAC_SHA256_PRF,
          "000102",
          "08c26012660a5d0a31747970652e676f6f676c65617069732e636f6d2f676f6f676c652e63727970746f2e74"
              + "696e6b2e486d61635072664b65791226120208031a2094e397d674deda6e965295698491a3feb69838"
              + "a35f1d48143f3c4cbad90eeb241801100118c2602003"),
      new TestVector(
          PredefinedSignatureParameters.ED25519,
          "000102",
          "08c260128e010a84010a38747970652e676f6f676c65617069732e636f6d2f676f6f676c652e63727970746f"
              + "2e74696e6b2e45643235353139507269766174654b65791246122094e397d674deda6e965295698491"
              + "a3feb69838a35f1d48143f3c4cbad90eeb241a221220c9855bf7fcb4f975e61eac19a530d490f276dd"
              + "cb1908fcf2ca13329981d58bab1802100118c2602001"),
      new TestVector(
          PredefinedStreamingAeadParameters.AES256_GCM_HKDF_1MB,
          "000102",
          "08c26012780a6f0a3d747970652e676f6f676c65617069732e636f6d2f676f6f676c652e63727970746f2e74"
              + "696e6b2e41657347636d486b646653747265616d696e674b6579122c120808808040102018031a2094"
              + "e397d674deda6e965295698491a3feb69838a35f1d48143f3c4cbad90eeb241801100118c2602003"),
      // TODO(tholenst): Test FFX FF1
    };
  }

  @DataPoints("allTests")
  public static final TestVector[] ALL_TEST_VECTORS = exceptionIsBug(() -> createTestVectors());

  @Theory
  public void deriveKeyset_isAsExpected(@FromDataPoints("allTests") TestVector t) throws Exception {
    Integer idRequirement = null;
    if (t.derivedKeyParameters.hasIdRequirement()) {
      idRequirement = 12354;
    }
    PrfBasedKeyDerivationParameters derivationParameters =
        PrfBasedKeyDerivationParameters.builder()
            .setDerivedKeyParameters(t.derivedKeyParameters)
            .setPrfParameters(FIXED_PRF_KEY.getParameters())
            .build();

    PrfBasedKeyDerivationKey keyDerivationKey =
        PrfBasedKeyDerivationKey.create(derivationParameters, FIXED_PRF_KEY, idRequirement);
    KeysetHandle keyset =
        KeysetHandle.newBuilder()
            .addEntry(KeysetHandle.importKey(keyDerivationKey).withFixedId(12354).makePrimary())
            .build();
    KeysetDeriver deriver = keyset.getPrimitive(KeysetDeriver.class);

    KeysetHandle derivedKeyset = deriver.deriveKeyset(Hex.decode(t.inputHex));

    assertThat(derivedKeyset.size()).isEqualTo(1);
    assertThat(derivedKeyset.getAt(0).getKey().getParameters()).isEqualTo(t.derivedKeyParameters);

    KeysetHandle expectedKeyset =
        TinkProtoKeysetFormat.parseKeyset(
            Hex.decode(t.resultingKeysetHex), InsecureSecretKeyAccess.get());

    String encodedDerivedKeyset =
        Hex.encode(
            TinkProtoKeysetFormat.serializeKeyset(derivedKeyset, InsecureSecretKeyAccess.get()));

    assertWithMessage("Correct hex-encoded derived keyset: " + encodedDerivedKeyset)
        .that(derivedKeyset.equalsKeyset(expectedKeyset))
        .isTrue();
  }

  // TODO(tholenst): Make sure tests are exhaustive
}
