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

package com.google.crypto.tink;

import static com.google.common.truth.Truth.assertThat;
import static com.google.crypto.tink.internal.TinkBugException.exceptionIsBug;

import com.google.crypto.tink.aead.AesCtrHmacAeadParameters;
import com.google.crypto.tink.aead.AesEaxParameters;
import com.google.crypto.tink.aead.AesGcmParameters;
import com.google.crypto.tink.aead.AesGcmSivParameters;
import com.google.crypto.tink.aead.ChaCha20Poly1305Parameters;
import com.google.crypto.tink.aead.PredefinedAeadParameters;
import com.google.crypto.tink.aead.XChaCha20Poly1305Parameters;
import com.google.crypto.tink.config.TinkConfig;
import com.google.crypto.tink.daead.AesSivParameters;
import com.google.crypto.tink.daead.PredefinedDeterministicAeadParameters;
import com.google.crypto.tink.hybrid.HpkeParameters;
import com.google.crypto.tink.internal.Util;
import com.google.crypto.tink.jwt.JwtEcdsaParameters;
import com.google.crypto.tink.jwt.JwtHmacParameters;
import com.google.crypto.tink.jwt.JwtMacConfig;
import com.google.crypto.tink.jwt.JwtRsaSsaPkcs1Parameters;
import com.google.crypto.tink.jwt.JwtRsaSsaPssParameters;
import com.google.crypto.tink.jwt.JwtSignatureConfig;
import com.google.crypto.tink.mac.AesCmacParameters;
import com.google.crypto.tink.mac.HmacParameters;
import com.google.crypto.tink.mac.PredefinedMacParameters;
import com.google.crypto.tink.prf.PredefinedPrfParameters;
import com.google.crypto.tink.signature.EcdsaParameters;
import com.google.crypto.tink.signature.PredefinedSignatureParameters;
import com.google.crypto.tink.signature.RsaSsaPkcs1Parameters;
import com.google.crypto.tink.signature.RsaSsaPssParameters;
import com.google.crypto.tink.streamingaead.PredefinedStreamingAeadParameters;
import java.security.GeneralSecurityException;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.experimental.theories.DataPoints;
import org.junit.experimental.theories.FromDataPoints;
import org.junit.experimental.theories.Theories;
import org.junit.experimental.theories.Theory;
import org.junit.runner.RunWith;

/**
 * This test compares all KeyTemplates (available via {@code KeyTemplates.get("SomeString")} to
 * corresponding parameters objects.
 *
 * <p>This can be used to find {@link Parameters} object which correspond to results of {@code
 * KeyTemplates.get(s)} for a given string {@code s}: simply check the list in {@code TEMPLATES}
 * below: if a pair {@code (s,p)} is in this list, this means that {@code
 * KeyTemplates.get(s).toParameters()} is equal to {@code p}.
 */
@RunWith(Theories.class)
public final class KeyTemplatesAsParametersTest {
  public static final class Pair {
    Pair(String templateName, Parameters parameters) {
      this.templateName = templateName;
      this.parameters = parameters;
    }

    String templateName;
    Parameters parameters;

    @Override
    public String toString() {
      return templateName + ":" + parameters;
    }
  }

  @BeforeClass
  public static void registerTink() throws Exception {
    JwtMacConfig.register();
    JwtSignatureConfig.register();
    TinkConfig.register();
  }

  private static final List<Pair> createTemplates() throws GeneralSecurityException {
    List<Pair> result = new ArrayList<>();
    // Aead
    result.add(new Pair("AES128_GCM", PredefinedAeadParameters.AES128_GCM));
    result.add(new Pair("AES256_GCM", PredefinedAeadParameters.AES256_GCM));
    result.add(
        new Pair(
            "AES128_GCM_RAW",
            AesGcmParameters.builder()
                .setIvSizeBytes(12)
                .setKeySizeBytes(16)
                .setTagSizeBytes(16)
                .setVariant(AesGcmParameters.Variant.NO_PREFIX)
                .build()));
    result.add(
        new Pair(
            "AES256_GCM_RAW",
            AesGcmParameters.builder()
                .setIvSizeBytes(12)
                .setKeySizeBytes(32)
                .setTagSizeBytes(16)
                .setVariant(AesGcmParameters.Variant.NO_PREFIX)
                .build()));
    result.add(new Pair("AES128_EAX", PredefinedAeadParameters.AES128_EAX));
    result.add(new Pair("AES256_EAX", PredefinedAeadParameters.AES256_EAX));
    result.add(
        new Pair(
            "AES128_EAX_RAW",
            AesEaxParameters.builder()
                .setIvSizeBytes(16)
                .setKeySizeBytes(16)
                .setTagSizeBytes(16)
                .setVariant(AesEaxParameters.Variant.NO_PREFIX)
                .build()));
    result.add(
        new Pair(
            "AES256_EAX_RAW",
            AesEaxParameters.builder()
                .setIvSizeBytes(16)
                .setKeySizeBytes(32)
                .setTagSizeBytes(16)
                .setVariant(AesEaxParameters.Variant.NO_PREFIX)
                .build()));
    result.add(new Pair("AES128_CTR_HMAC_SHA256", PredefinedAeadParameters.AES128_CTR_HMAC_SHA256));
    result.add(new Pair("AES256_CTR_HMAC_SHA256", PredefinedAeadParameters.AES256_CTR_HMAC_SHA256));
    result.add(
        new Pair(
            "AES128_CTR_HMAC_SHA256_RAW",
            AesCtrHmacAeadParameters.builder()
                .setAesKeySizeBytes(16)
                .setHmacKeySizeBytes(32)
                .setTagSizeBytes(16)
                .setIvSizeBytes(16)
                .setHashType(AesCtrHmacAeadParameters.HashType.SHA256)
                .setVariant(AesCtrHmacAeadParameters.Variant.NO_PREFIX)
                .build()));
    result.add(
        new Pair(
            "AES256_CTR_HMAC_SHA256_RAW",
            AesCtrHmacAeadParameters.builder()
                .setAesKeySizeBytes(32)
                .setHmacKeySizeBytes(32)
                .setTagSizeBytes(32)
                .setIvSizeBytes(16)
                .setHashType(AesCtrHmacAeadParameters.HashType.SHA256)
                .setVariant(AesCtrHmacAeadParameters.Variant.NO_PREFIX)
                .build()));
    result.add(new Pair("CHACHA20_POLY1305", PredefinedAeadParameters.CHACHA20_POLY1305));
    result.add(
        new Pair(
            "CHACHA20_POLY1305_RAW",
            ChaCha20Poly1305Parameters.create(ChaCha20Poly1305Parameters.Variant.NO_PREFIX)));
    result.add(new Pair("XCHACHA20_POLY1305", PredefinedAeadParameters.XCHACHA20_POLY1305));
    result.add(
        new Pair(
            "XCHACHA20_POLY1305_RAW",
            XChaCha20Poly1305Parameters.create(XChaCha20Poly1305Parameters.Variant.NO_PREFIX)));
    // Mac
    result.add(new Pair("HMAC_SHA256_128BITTAG", PredefinedMacParameters.HMAC_SHA256_128BITTAG));
    result.add(
        new Pair(
            "HMAC_SHA256_128BITTAG_RAW",
            HmacParameters.builder()
                .setKeySizeBytes(32)
                .setTagSizeBytes(16)
                .setVariant(HmacParameters.Variant.NO_PREFIX)
                .setHashType(HmacParameters.HashType.SHA256)
                .build()));
    result.add(
        new Pair(
            "HMAC_SHA256_256BITTAG_RAW",
            HmacParameters.builder()
                .setKeySizeBytes(32)
                .setTagSizeBytes(32)
                .setVariant(HmacParameters.Variant.NO_PREFIX)
                .setHashType(HmacParameters.HashType.SHA256)
                .build()));
    result.add(
        new Pair(
            "HMAC_SHA512_128BITTAG",
            HmacParameters.builder()
                .setKeySizeBytes(64)
                .setTagSizeBytes(16)
                .setVariant(HmacParameters.Variant.TINK)
                .setHashType(HmacParameters.HashType.SHA512)
                .build()));
    result.add(
        new Pair(
            "HMAC_SHA512_128BITTAG_RAW",
            HmacParameters.builder()
                .setKeySizeBytes(64)
                .setTagSizeBytes(16)
                .setVariant(HmacParameters.Variant.NO_PREFIX)
                .setHashType(HmacParameters.HashType.SHA512)
                .build()));
    result.add(
        new Pair(
            "HMAC_SHA512_256BITTAG_RAW",
            HmacParameters.builder()
                .setKeySizeBytes(64)
                .setTagSizeBytes(32)
                .setVariant(HmacParameters.Variant.NO_PREFIX)
                .setHashType(HmacParameters.HashType.SHA512)
                .build()));
    result.add(
        new Pair(
            "HMAC_SHA512_512BITTAG_RAW",
            HmacParameters.builder()
                .setKeySizeBytes(64)
                .setTagSizeBytes(64)
                .setVariant(HmacParameters.Variant.NO_PREFIX)
                .setHashType(HmacParameters.HashType.SHA512)
                .build()));
    result.add(new Pair("HMAC_SHA256_256BITTAG", PredefinedMacParameters.HMAC_SHA256_256BITTAG));
    result.add(new Pair("HMAC_SHA512_256BITTAG", PredefinedMacParameters.HMAC_SHA512_256BITTAG));
    result.add(new Pair("HMAC_SHA512_512BITTAG", PredefinedMacParameters.HMAC_SHA512_512BITTAG));
    result.add(new Pair("AES_CMAC", PredefinedMacParameters.AES_CMAC));
    result.add(new Pair("AES256_CMAC", PredefinedMacParameters.AES_CMAC));
    result.add(
        new Pair(
            "AES256_CMAC_RAW",
            AesCmacParameters.builder()
                .setKeySizeBytes(32)
                .setTagSizeBytes(16)
                .setVariant(AesCmacParameters.Variant.NO_PREFIX)
                .build()));
    // DeterministicAead
    result.add(new Pair("AES256_SIV", PredefinedDeterministicAeadParameters.AES256_SIV));
    result.add(
        new Pair(
            "AES256_SIV_RAW",
            AesSivParameters.builder()
                .setKeySizeBytes(64)
                .setVariant(AesSivParameters.Variant.NO_PREFIX)
                .build()));
    // StreamingAead
    result.add(
        new Pair(
            "AES128_CTR_HMAC_SHA256_4KB",
            PredefinedStreamingAeadParameters.AES128_CTR_HMAC_SHA256_4KB));
    result.add(
        new Pair(
            "AES128_CTR_HMAC_SHA256_1MB",
            PredefinedStreamingAeadParameters.AES128_CTR_HMAC_SHA256_1MB));
    result.add(
        new Pair(
            "AES256_CTR_HMAC_SHA256_4KB",
            PredefinedStreamingAeadParameters.AES256_CTR_HMAC_SHA256_4KB));
    result.add(
        new Pair(
            "AES256_CTR_HMAC_SHA256_1MB",
            PredefinedStreamingAeadParameters.AES256_CTR_HMAC_SHA256_1MB));
    result.add(
        new Pair("AES128_GCM_HKDF_4KB", PredefinedStreamingAeadParameters.AES128_GCM_HKDF_4KB));
    result.add(
        new Pair("AES128_GCM_HKDF_1MB", PredefinedStreamingAeadParameters.AES128_GCM_HKDF_1MB));
    result.add(
        new Pair("AES256_GCM_HKDF_4KB", PredefinedStreamingAeadParameters.AES256_GCM_HKDF_4KB));
    result.add(
        new Pair("AES256_GCM_HKDF_1MB", PredefinedStreamingAeadParameters.AES256_GCM_HKDF_1MB));
    // Prf
    result.add(new Pair("HKDF_SHA256", PredefinedPrfParameters.HKDF_SHA256));
    result.add(new Pair("HMAC_SHA256_PRF", PredefinedPrfParameters.HMAC_SHA256_PRF));
    result.add(new Pair("HMAC_SHA512_PRF", PredefinedPrfParameters.HMAC_SHA512_PRF));
    result.add(new Pair("AES256_CMAC_PRF", PredefinedPrfParameters.AES_CMAC_PRF));
    result.add(new Pair("AES_CMAC_PRF", PredefinedPrfParameters.AES_CMAC_PRF));
    // Signature
    result.add(new Pair("ECDSA_P256", PredefinedSignatureParameters.ECDSA_P256));
    result.add(
        new Pair("ECDSA_P256_IEEE_P1363", PredefinedSignatureParameters.ECDSA_P256_IEEE_P1363));
    result.add(
        new Pair(
            "ECDSA_P256_IEEE_P1363_WITHOUT_PREFIX",
            PredefinedSignatureParameters.ECDSA_P256_IEEE_P1363_WITHOUT_PREFIX));
    result.add(
        new Pair(
            "ECDSA_P256_RAW",
            EcdsaParameters.builder()
                .setHashType(EcdsaParameters.HashType.SHA256)
                .setCurveType(EcdsaParameters.CurveType.NIST_P256)
                .setSignatureEncoding(EcdsaParameters.SignatureEncoding.IEEE_P1363)
                .setVariant(EcdsaParameters.Variant.NO_PREFIX)
                .build()));
    result.add(new Pair("ECDSA_P384", PredefinedSignatureParameters.ECDSA_P384));
    result.add(
        new Pair("ECDSA_P384_IEEE_P1363", PredefinedSignatureParameters.ECDSA_P384_IEEE_P1363));
    result.add(
        new Pair(
            "ECDSA_P384_SHA384",
            EcdsaParameters.builder()
                .setHashType(EcdsaParameters.HashType.SHA384)
                .setCurveType(EcdsaParameters.CurveType.NIST_P384)
                .setSignatureEncoding(EcdsaParameters.SignatureEncoding.DER)
                .setVariant(EcdsaParameters.Variant.TINK)
                .build()));
    result.add(
        new Pair(
            "ECDSA_P384_SHA512",
            EcdsaParameters.builder()
                .setHashType(EcdsaParameters.HashType.SHA512)
                .setCurveType(EcdsaParameters.CurveType.NIST_P384)
                .setSignatureEncoding(EcdsaParameters.SignatureEncoding.DER)
                .setVariant(EcdsaParameters.Variant.TINK)
                .build()));
    result.add(new Pair("ECDSA_P521", PredefinedSignatureParameters.ECDSA_P521));
    result.add(
        new Pair("ECDSA_P521_IEEE_P1363", PredefinedSignatureParameters.ECDSA_P521_IEEE_P1363));
    result.add(new Pair("ED25519", PredefinedSignatureParameters.ED25519));
    result.add(new Pair("ED25519_RAW", PredefinedSignatureParameters.ED25519WithRawOutput));
    result.add(
        new Pair("ED25519WithRawOutput", PredefinedSignatureParameters.ED25519WithRawOutput));
    result.add(
        new Pair(
            "RSA_SSA_PKCS1_3072_SHA256_F4",
            PredefinedSignatureParameters.RSA_SSA_PKCS1_3072_SHA256_F4));
    result.add(
        new Pair(
            "RSA_SSA_PKCS1_3072_SHA256_F4_RAW",
            RsaSsaPkcs1Parameters.builder()
                .setHashType(RsaSsaPkcs1Parameters.HashType.SHA256)
                .setModulusSizeBits(3072)
                .setPublicExponent(RsaSsaPkcs1Parameters.F4)
                .setVariant(RsaSsaPkcs1Parameters.Variant.NO_PREFIX)
                .build()));
    result.add(
        new Pair(
            "RSA_SSA_PKCS1_3072_SHA256_F4_WITHOUT_PREFIX",
            PredefinedSignatureParameters.RSA_SSA_PKCS1_3072_SHA256_F4_WITHOUT_PREFIX));
    result.add(
        new Pair(
            "RSA_SSA_PKCS1_4096_SHA512_F4",
            PredefinedSignatureParameters.RSA_SSA_PKCS1_4096_SHA512_F4));
    result.add(
        new Pair(
            "RSA_SSA_PKCS1_4096_SHA512_F4_RAW",
            RsaSsaPkcs1Parameters.builder()
                .setHashType(RsaSsaPkcs1Parameters.HashType.SHA512)
                .setModulusSizeBits(4096)
                .setPublicExponent(RsaSsaPkcs1Parameters.F4)
                .setVariant(RsaSsaPkcs1Parameters.Variant.NO_PREFIX)
                .build()));
    result.add(
        new Pair(
            "RSA_SSA_PSS_3072_SHA256_F4",
            RsaSsaPssParameters.builder()
                .setSigHashType(RsaSsaPssParameters.HashType.SHA256)
                .setMgf1HashType(RsaSsaPssParameters.HashType.SHA256)
                .setSaltLengthBytes(32)
                .setModulusSizeBits(3072)
                .setPublicExponent(RsaSsaPssParameters.F4)
                .setVariant(RsaSsaPssParameters.Variant.TINK)
                .build()));
    result.add(
        new Pair(
            "RSA_SSA_PSS_3072_SHA256_F4_RAW",
            RsaSsaPssParameters.builder()
                .setSigHashType(RsaSsaPssParameters.HashType.SHA256)
                .setMgf1HashType(RsaSsaPssParameters.HashType.SHA256)
                .setSaltLengthBytes(32)
                .setModulusSizeBits(3072)
                .setPublicExponent(RsaSsaPssParameters.F4)
                .setVariant(RsaSsaPssParameters.Variant.NO_PREFIX)
                .build()));
    result.add(
        new Pair(
            "RSA_SSA_PSS_3072_SHA256_SHA256_32_F4",
            PredefinedSignatureParameters.RSA_SSA_PSS_3072_SHA256_SHA256_32_F4));
    result.add(
        new Pair(
            "RSA_SSA_PSS_4096_SHA512_F4",
            RsaSsaPssParameters.builder()
                .setSigHashType(RsaSsaPssParameters.HashType.SHA512)
                .setMgf1HashType(RsaSsaPssParameters.HashType.SHA512)
                .setSaltLengthBytes(64)
                .setModulusSizeBits(4096)
                .setPublicExponent(RsaSsaPssParameters.F4)
                .setVariant(RsaSsaPssParameters.Variant.TINK)
                .build()));
    result.add(
        new Pair(
            "RSA_SSA_PSS_4096_SHA512_F4_RAW",
            RsaSsaPssParameters.builder()
                .setSigHashType(RsaSsaPssParameters.HashType.SHA512)
                .setMgf1HashType(RsaSsaPssParameters.HashType.SHA512)
                .setSaltLengthBytes(64)
                .setModulusSizeBits(4096)
                .setPublicExponent(RsaSsaPssParameters.F4)
                .setVariant(RsaSsaPssParameters.Variant.NO_PREFIX)
                .build()));
    result.add(
        new Pair(
            "RSA_SSA_PSS_4096_SHA512_SHA512_64_F4",
            PredefinedSignatureParameters.RSA_SSA_PSS_4096_SHA512_SHA512_64_F4));

    if (Util.isAndroid()) {
      result.add(
          new Pair(
              "AES128_GCM_SIV",
              AesGcmSivParameters.builder()
                  .setKeySizeBytes(16)
                  .setVariant(AesGcmSivParameters.Variant.TINK)
                  .build()));
      result.add(
          new Pair(
              "AES128_GCM_SIV_RAW",
              AesGcmSivParameters.builder()
                  .setKeySizeBytes(16)
                  .setVariant(AesGcmSivParameters.Variant.NO_PREFIX)
                  .build()));
      result.add(
          new Pair(
              "AES256_GCM_SIV",
              AesGcmSivParameters.builder()
                  .setKeySizeBytes(32)
                  .setVariant(AesGcmSivParameters.Variant.TINK)
                  .build()));
      result.add(
          new Pair(
              "AES256_GCM_SIV_RAW",
              AesGcmSivParameters.builder()
                  .setKeySizeBytes(32)
                  .setVariant(AesGcmSivParameters.Variant.NO_PREFIX)
                  .build()));
    }
    // Hybrid
    result.add(
        new Pair(
            "DHKEM_P256_HKDF_SHA256_HKDF_SHA256_AES_128_GCM",
            HpkeParameters.builder()
                .setVariant(HpkeParameters.Variant.TINK)
                .setKemId(HpkeParameters.KemId.DHKEM_P256_HKDF_SHA256)
                .setKdfId(HpkeParameters.KdfId.HKDF_SHA256)
                .setAeadId(HpkeParameters.AeadId.AES_128_GCM)
                .build()));
    result.add(
        new Pair(
            "DHKEM_P256_HKDF_SHA256_HKDF_SHA256_AES_128_GCM_RAW",
            HpkeParameters.builder()
                .setVariant(HpkeParameters.Variant.NO_PREFIX)
                .setKemId(HpkeParameters.KemId.DHKEM_P256_HKDF_SHA256)
                .setKdfId(HpkeParameters.KdfId.HKDF_SHA256)
                .setAeadId(HpkeParameters.AeadId.AES_128_GCM)
                .build()));
    result.add(
        new Pair(
            "DHKEM_P256_HKDF_SHA256_HKDF_SHA256_AES_256_GCM",
            HpkeParameters.builder()
                .setVariant(HpkeParameters.Variant.TINK)
                .setKemId(HpkeParameters.KemId.DHKEM_P256_HKDF_SHA256)
                .setKdfId(HpkeParameters.KdfId.HKDF_SHA256)
                .setAeadId(HpkeParameters.AeadId.AES_256_GCM)
                .build()));
    result.add(
        new Pair(
            "DHKEM_P256_HKDF_SHA256_HKDF_SHA256_AES_256_GCM_RAW",
            HpkeParameters.builder()
                .setVariant(HpkeParameters.Variant.NO_PREFIX)
                .setKemId(HpkeParameters.KemId.DHKEM_P256_HKDF_SHA256)
                .setKdfId(HpkeParameters.KdfId.HKDF_SHA256)
                .setAeadId(HpkeParameters.AeadId.AES_256_GCM)
                .build()));
    result.add(
        new Pair(
            "DHKEM_P384_HKDF_SHA384_HKDF_SHA384_AES_128_GCM",
            HpkeParameters.builder()
                .setVariant(HpkeParameters.Variant.TINK)
                .setKemId(HpkeParameters.KemId.DHKEM_P384_HKDF_SHA384)
                .setKdfId(HpkeParameters.KdfId.HKDF_SHA384)
                .setAeadId(HpkeParameters.AeadId.AES_128_GCM)
                .build()));
    result.add(
        new Pair(
            "DHKEM_P384_HKDF_SHA384_HKDF_SHA384_AES_128_GCM_RAW",
            HpkeParameters.builder()
                .setVariant(HpkeParameters.Variant.NO_PREFIX)
                .setKemId(HpkeParameters.KemId.DHKEM_P384_HKDF_SHA384)
                .setKdfId(HpkeParameters.KdfId.HKDF_SHA384)
                .setAeadId(HpkeParameters.AeadId.AES_128_GCM)
                .build()));
    result.add(
        new Pair(
            "DHKEM_P384_HKDF_SHA384_HKDF_SHA384_AES_256_GCM",
            HpkeParameters.builder()
                .setVariant(HpkeParameters.Variant.TINK)
                .setKemId(HpkeParameters.KemId.DHKEM_P384_HKDF_SHA384)
                .setKdfId(HpkeParameters.KdfId.HKDF_SHA384)
                .setAeadId(HpkeParameters.AeadId.AES_256_GCM)
                .build()));
    result.add(
        new Pair(
            "DHKEM_P384_HKDF_SHA384_HKDF_SHA384_AES_256_GCM_RAW",
            HpkeParameters.builder()
                .setVariant(HpkeParameters.Variant.NO_PREFIX)
                .setKemId(HpkeParameters.KemId.DHKEM_P384_HKDF_SHA384)
                .setKdfId(HpkeParameters.KdfId.HKDF_SHA384)
                .setAeadId(HpkeParameters.AeadId.AES_256_GCM)
                .build()));
    result.add(
        new Pair(
            "DHKEM_P521_HKDF_SHA512_HKDF_SHA512_AES_128_GCM",
            HpkeParameters.builder()
                .setVariant(HpkeParameters.Variant.TINK)
                .setKemId(HpkeParameters.KemId.DHKEM_P521_HKDF_SHA512)
                .setKdfId(HpkeParameters.KdfId.HKDF_SHA512)
                .setAeadId(HpkeParameters.AeadId.AES_128_GCM)
                .build()));
    result.add(
        new Pair(
            "DHKEM_P521_HKDF_SHA512_HKDF_SHA512_AES_128_GCM_RAW",
            HpkeParameters.builder()
                .setVariant(HpkeParameters.Variant.NO_PREFIX)
                .setKemId(HpkeParameters.KemId.DHKEM_P521_HKDF_SHA512)
                .setKdfId(HpkeParameters.KdfId.HKDF_SHA512)
                .setAeadId(HpkeParameters.AeadId.AES_128_GCM)
                .build()));
    result.add(
        new Pair(
            "DHKEM_P521_HKDF_SHA512_HKDF_SHA512_AES_256_GCM",
            HpkeParameters.builder()
                .setVariant(HpkeParameters.Variant.TINK)
                .setKemId(HpkeParameters.KemId.DHKEM_P521_HKDF_SHA512)
                .setKdfId(HpkeParameters.KdfId.HKDF_SHA512)
                .setAeadId(HpkeParameters.AeadId.AES_256_GCM)
                .build()));
    result.add(
        new Pair(
            "DHKEM_P521_HKDF_SHA512_HKDF_SHA512_AES_256_GCM_RAW",
            HpkeParameters.builder()
                .setVariant(HpkeParameters.Variant.NO_PREFIX)
                .setKemId(HpkeParameters.KemId.DHKEM_P521_HKDF_SHA512)
                .setKdfId(HpkeParameters.KdfId.HKDF_SHA512)
                .setAeadId(HpkeParameters.AeadId.AES_256_GCM)
                .build()));
    result.add(
        new Pair(
            "DHKEM_X25519_HKDF_SHA256_HKDF_SHA256_AES_128_GCM",
            HpkeParameters.builder()
                .setVariant(HpkeParameters.Variant.TINK)
                .setKemId(HpkeParameters.KemId.DHKEM_X25519_HKDF_SHA256)
                .setKdfId(HpkeParameters.KdfId.HKDF_SHA256)
                .setAeadId(HpkeParameters.AeadId.AES_128_GCM)
                .build()));
    result.add(
        new Pair(
            "DHKEM_X25519_HKDF_SHA256_HKDF_SHA256_AES_128_GCM_RAW",
            HpkeParameters.builder()
                .setVariant(HpkeParameters.Variant.NO_PREFIX)
                .setKemId(HpkeParameters.KemId.DHKEM_X25519_HKDF_SHA256)
                .setKdfId(HpkeParameters.KdfId.HKDF_SHA256)
                .setAeadId(HpkeParameters.AeadId.AES_128_GCM)
                .build()));
    result.add(
        new Pair(
            "DHKEM_X25519_HKDF_SHA256_HKDF_SHA256_AES_256_GCM",
            HpkeParameters.builder()
                .setVariant(HpkeParameters.Variant.TINK)
                .setKemId(HpkeParameters.KemId.DHKEM_X25519_HKDF_SHA256)
                .setKdfId(HpkeParameters.KdfId.HKDF_SHA256)
                .setAeadId(HpkeParameters.AeadId.AES_256_GCM)
                .build()));
    result.add(
        new Pair(
            "DHKEM_X25519_HKDF_SHA256_HKDF_SHA256_AES_256_GCM_RAW",
            HpkeParameters.builder()
                .setVariant(HpkeParameters.Variant.NO_PREFIX)
                .setKemId(HpkeParameters.KemId.DHKEM_X25519_HKDF_SHA256)
                .setKdfId(HpkeParameters.KdfId.HKDF_SHA256)
                .setAeadId(HpkeParameters.AeadId.AES_256_GCM)
                .build()));
    result.add(
        new Pair(
            "DHKEM_X25519_HKDF_SHA256_HKDF_SHA256_CHACHA20_POLY1305",
            HpkeParameters.builder()
                .setVariant(HpkeParameters.Variant.TINK)
                .setKemId(HpkeParameters.KemId.DHKEM_X25519_HKDF_SHA256)
                .setKdfId(HpkeParameters.KdfId.HKDF_SHA256)
                .setAeadId(HpkeParameters.AeadId.CHACHA20_POLY1305)
                .build()));
    result.add(
        new Pair(
            "DHKEM_X25519_HKDF_SHA256_HKDF_SHA256_CHACHA20_POLY1305_RAW",
            HpkeParameters.builder()
                .setVariant(HpkeParameters.Variant.NO_PREFIX)
                .setKemId(HpkeParameters.KemId.DHKEM_X25519_HKDF_SHA256)
                .setKdfId(HpkeParameters.KdfId.HKDF_SHA256)
                .setAeadId(HpkeParameters.AeadId.CHACHA20_POLY1305)
                .build()));

    // JWT Mac
    result.add(
        new Pair(
            "JWT_HS256",
            JwtHmacParameters.builder()
                .setKeySizeBytes(32)
                .setAlgorithm(JwtHmacParameters.Algorithm.HS256)
                .setKidStrategy(JwtHmacParameters.KidStrategy.BASE64_ENCODED_KEY_ID)
                .build()));
    result.add(
        new Pair(
            "JWT_HS256_RAW",
            JwtHmacParameters.builder()
                .setKeySizeBytes(32)
                .setAlgorithm(JwtHmacParameters.Algorithm.HS256)
                .setKidStrategy(JwtHmacParameters.KidStrategy.IGNORED)
                .build()));
    result.add(
        new Pair(
            "JWT_HS384",
            JwtHmacParameters.builder()
                .setKeySizeBytes(48)
                .setAlgorithm(JwtHmacParameters.Algorithm.HS384)
                .setKidStrategy(JwtHmacParameters.KidStrategy.BASE64_ENCODED_KEY_ID)
                .build()));
    result.add(
        new Pair(
            "JWT_HS384_RAW",
            JwtHmacParameters.builder()
                .setKeySizeBytes(48)
                .setAlgorithm(JwtHmacParameters.Algorithm.HS384)
                .setKidStrategy(JwtHmacParameters.KidStrategy.IGNORED)
                .build()));
    result.add(
        new Pair(
            "JWT_HS512",
            JwtHmacParameters.builder()
                .setKeySizeBytes(64)
                .setAlgorithm(JwtHmacParameters.Algorithm.HS512)
                .setKidStrategy(JwtHmacParameters.KidStrategy.BASE64_ENCODED_KEY_ID)
                .build()));
    result.add(
        new Pair(
            "JWT_HS512_RAW",
            JwtHmacParameters.builder()
                .setKeySizeBytes(64)
                .setAlgorithm(JwtHmacParameters.Algorithm.HS512)
                .setKidStrategy(JwtHmacParameters.KidStrategy.IGNORED)
                .build()));
    // JWT Signature
    result.add(
        new Pair(
            "JWT_ES256",
            JwtEcdsaParameters.builder()
                .setAlgorithm(JwtEcdsaParameters.Algorithm.ES256)
                .setKidStrategy(JwtEcdsaParameters.KidStrategy.BASE64_ENCODED_KEY_ID)
                .build()));
    result.add(
        new Pair(
            "JWT_ES256_RAW",
            JwtEcdsaParameters.builder()
                .setAlgorithm(JwtEcdsaParameters.Algorithm.ES256)
                .setKidStrategy(JwtEcdsaParameters.KidStrategy.IGNORED)
                .build()));
    result.add(
        new Pair(
            "JWT_ES384",
            JwtEcdsaParameters.builder()
                .setAlgorithm(JwtEcdsaParameters.Algorithm.ES384)
                .setKidStrategy(JwtEcdsaParameters.KidStrategy.BASE64_ENCODED_KEY_ID)
                .build()));
    result.add(
        new Pair(
            "JWT_ES384_RAW",
            JwtEcdsaParameters.builder()
                .setAlgorithm(JwtEcdsaParameters.Algorithm.ES384)
                .setKidStrategy(JwtEcdsaParameters.KidStrategy.IGNORED)
                .build()));
    result.add(
        new Pair(
            "JWT_ES512",
            JwtEcdsaParameters.builder()
                .setAlgorithm(JwtEcdsaParameters.Algorithm.ES512)
                .setKidStrategy(JwtEcdsaParameters.KidStrategy.BASE64_ENCODED_KEY_ID)
                .build()));
    result.add(
        new Pair(
            "JWT_ES512_RAW",
            JwtEcdsaParameters.builder()
                .setAlgorithm(JwtEcdsaParameters.Algorithm.ES512)
                .setKidStrategy(JwtEcdsaParameters.KidStrategy.IGNORED)
                .build()));
    result.add(
        new Pair(
            "JWT_PS256_2048_F4",
            JwtRsaSsaPssParameters.builder()
                .setModulusSizeBits(2048)
                .setPublicExponent(JwtRsaSsaPssParameters.F4)
                .setAlgorithm(JwtRsaSsaPssParameters.Algorithm.PS256)
                .setKidStrategy(JwtRsaSsaPssParameters.KidStrategy.BASE64_ENCODED_KEY_ID)
                .build()));
    result.add(
        new Pair(
            "JWT_PS256_2048_F4_RAW",
            JwtRsaSsaPssParameters.builder()
                .setModulusSizeBits(2048)
                .setPublicExponent(JwtRsaSsaPssParameters.F4)
                .setAlgorithm(JwtRsaSsaPssParameters.Algorithm.PS256)
                .setKidStrategy(JwtRsaSsaPssParameters.KidStrategy.IGNORED)
                .build()));
    result.add(
        new Pair(
            "JWT_PS256_3072_F4",
            JwtRsaSsaPssParameters.builder()
                .setModulusSizeBits(3072)
                .setPublicExponent(JwtRsaSsaPssParameters.F4)
                .setAlgorithm(JwtRsaSsaPssParameters.Algorithm.PS256)
                .setKidStrategy(JwtRsaSsaPssParameters.KidStrategy.BASE64_ENCODED_KEY_ID)
                .build()));
    result.add(
        new Pair(
            "JWT_PS256_3072_F4_RAW",
            JwtRsaSsaPssParameters.builder()
                .setModulusSizeBits(3072)
                .setPublicExponent(JwtRsaSsaPssParameters.F4)
                .setAlgorithm(JwtRsaSsaPssParameters.Algorithm.PS256)
                .setKidStrategy(JwtRsaSsaPssParameters.KidStrategy.IGNORED)
                .build()));
    result.add(
        new Pair(
            "JWT_PS384_3072_F4",
            JwtRsaSsaPssParameters.builder()
                .setModulusSizeBits(3072)
                .setPublicExponent(JwtRsaSsaPssParameters.F4)
                .setAlgorithm(JwtRsaSsaPssParameters.Algorithm.PS384)
                .setKidStrategy(JwtRsaSsaPssParameters.KidStrategy.BASE64_ENCODED_KEY_ID)
                .build()));
    result.add(
        new Pair(
            "JWT_PS384_3072_F4_RAW",
            JwtRsaSsaPssParameters.builder()
                .setModulusSizeBits(3072)
                .setPublicExponent(JwtRsaSsaPssParameters.F4)
                .setAlgorithm(JwtRsaSsaPssParameters.Algorithm.PS384)
                .setKidStrategy(JwtRsaSsaPssParameters.KidStrategy.IGNORED)
                .build()));
    result.add(
        new Pair(
            "JWT_PS512_4096_F4",
            JwtRsaSsaPssParameters.builder()
                .setModulusSizeBits(4096)
                .setPublicExponent(JwtRsaSsaPssParameters.F4)
                .setAlgorithm(JwtRsaSsaPssParameters.Algorithm.PS512)
                .setKidStrategy(JwtRsaSsaPssParameters.KidStrategy.BASE64_ENCODED_KEY_ID)
                .build()));
    result.add(
        new Pair(
            "JWT_PS512_4096_F4_RAW",
            JwtRsaSsaPssParameters.builder()
                .setModulusSizeBits(4096)
                .setPublicExponent(JwtRsaSsaPssParameters.F4)
                .setAlgorithm(JwtRsaSsaPssParameters.Algorithm.PS512)
                .setKidStrategy(JwtRsaSsaPssParameters.KidStrategy.IGNORED)
                .build()));
    result.add(
        new Pair(
            "JWT_RS256_2048_F4",
            JwtRsaSsaPkcs1Parameters.builder()
                .setModulusSizeBits(2048)
                .setPublicExponent(JwtRsaSsaPkcs1Parameters.F4)
                .setAlgorithm(JwtRsaSsaPkcs1Parameters.Algorithm.RS256)
                .setKidStrategy(JwtRsaSsaPkcs1Parameters.KidStrategy.BASE64_ENCODED_KEY_ID)
                .build()));
    result.add(
        new Pair(
            "JWT_RS256_2048_F4_RAW",
            JwtRsaSsaPkcs1Parameters.builder()
                .setModulusSizeBits(2048)
                .setPublicExponent(JwtRsaSsaPkcs1Parameters.F4)
                .setAlgorithm(JwtRsaSsaPkcs1Parameters.Algorithm.RS256)
                .setKidStrategy(JwtRsaSsaPkcs1Parameters.KidStrategy.IGNORED)
                .build()));
    result.add(
        new Pair(
            "JWT_RS256_3072_F4",
            JwtRsaSsaPkcs1Parameters.builder()
                .setModulusSizeBits(3072)
                .setPublicExponent(JwtRsaSsaPkcs1Parameters.F4)
                .setAlgorithm(JwtRsaSsaPkcs1Parameters.Algorithm.RS256)
                .setKidStrategy(JwtRsaSsaPkcs1Parameters.KidStrategy.BASE64_ENCODED_KEY_ID)
                .build()));
    result.add(
        new Pair(
            "JWT_RS256_3072_F4_RAW",
            JwtRsaSsaPkcs1Parameters.builder()
                .setModulusSizeBits(3072)
                .setPublicExponent(JwtRsaSsaPkcs1Parameters.F4)
                .setAlgorithm(JwtRsaSsaPkcs1Parameters.Algorithm.RS256)
                .setKidStrategy(JwtRsaSsaPkcs1Parameters.KidStrategy.IGNORED)
                .build()));
    result.add(
        new Pair(
            "JWT_RS384_3072_F4",
            JwtRsaSsaPkcs1Parameters.builder()
                .setModulusSizeBits(3072)
                .setPublicExponent(JwtRsaSsaPkcs1Parameters.F4)
                .setAlgorithm(JwtRsaSsaPkcs1Parameters.Algorithm.RS384)
                .setKidStrategy(JwtRsaSsaPkcs1Parameters.KidStrategy.BASE64_ENCODED_KEY_ID)
                .build()));
    result.add(
        new Pair(
            "JWT_RS384_3072_F4_RAW",
            JwtRsaSsaPkcs1Parameters.builder()
                .setModulusSizeBits(3072)
                .setPublicExponent(JwtRsaSsaPkcs1Parameters.F4)
                .setAlgorithm(JwtRsaSsaPkcs1Parameters.Algorithm.RS384)
                .setKidStrategy(JwtRsaSsaPkcs1Parameters.KidStrategy.IGNORED)
                .build()));
    result.add(
        new Pair(
            "JWT_RS512_4096_F4",
            JwtRsaSsaPkcs1Parameters.builder()
                .setModulusSizeBits(4096)
                .setPublicExponent(JwtRsaSsaPkcs1Parameters.F4)
                .setAlgorithm(JwtRsaSsaPkcs1Parameters.Algorithm.RS512)
                .setKidStrategy(JwtRsaSsaPkcs1Parameters.KidStrategy.BASE64_ENCODED_KEY_ID)
                .build()));
    result.add(
        new Pair(
            "JWT_RS512_4096_F4_RAW",
            JwtRsaSsaPkcs1Parameters.builder()
                .setModulusSizeBits(4096)
                .setPublicExponent(JwtRsaSsaPkcs1Parameters.F4)
                .setAlgorithm(JwtRsaSsaPkcs1Parameters.Algorithm.RS512)
                .setKidStrategy(JwtRsaSsaPkcs1Parameters.KidStrategy.IGNORED)
                .build()));
    return result;
  }

  @DataPoints("EquivalentPairs")
  public static final List<Pair> templates = exceptionIsBug(() -> createTemplates());

  @Theory
  public void testParametersEqualsKeyTemplate(@FromDataPoints("EquivalentPairs") Pair p)
      throws Exception {
    assertThat(KeyTemplates.get(p.templateName).toParameters()).isEqualTo(p.parameters);
  }

  private static Set<String> getAllTestedNames() {
    Set<String> result = new HashSet<>();
    for (Pair p : templates) {
      result.add(p.templateName);
    }
    return result;
  }

  private static Set<String> getUntestedNames() {
    Set<String> result = new HashSet<>();
    result.add("ECIES_P256_COMPRESSED_HKDF_HMAC_SHA256_AES128_CTR_HMAC_SHA256");
    result.add("ECIES_P256_COMPRESSED_HKDF_HMAC_SHA256_AES128_CTR_HMAC_SHA256_RAW");
    result.add("ECIES_P256_COMPRESSED_HKDF_HMAC_SHA256_AES128_GCM");
    result.add("ECIES_P256_COMPRESSED_HKDF_HMAC_SHA256_AES128_GCM_RAW");
    result.add("ECIES_P256_HKDF_HMAC_SHA256_AES128_CTR_HMAC_SHA256");
    result.add("ECIES_P256_HKDF_HMAC_SHA256_AES128_CTR_HMAC_SHA256_RAW");
    result.add("ECIES_P256_HKDF_HMAC_SHA256_AES128_GCM");
    result.add("ECIES_P256_HKDF_HMAC_SHA256_AES128_GCM_COMPRESSED_WITHOUT_PREFIX");
    result.add("ECIES_P256_HKDF_HMAC_SHA256_AES128_GCM_RAW");
    return result;
  }

  /** Tests that we test all available names */
  @Test
  public void testCompletenessOfThisTest() throws Exception {
    Set<String> testedNames = getAllTestedNames();
    Set<String> untestedNames = getUntestedNames();

    // Note that this means the two sets do not intersect.
    assertThat(testedNames).containsNoneIn(untestedNames);

    Set<String> testedPlusMissing = new HashSet<>();
    testedPlusMissing.addAll(testedNames);
    testedPlusMissing.addAll(untestedNames);
    assertThat(Registry.keyTemplateMap().keySet()).containsExactlyElementsIn(testedPlusMissing);
  }
}
