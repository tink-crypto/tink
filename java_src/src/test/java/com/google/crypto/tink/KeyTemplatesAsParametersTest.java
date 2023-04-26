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

import com.google.crypto.tink.aead.PredefinedAeadParameters;
import com.google.crypto.tink.config.TinkConfig;
import com.google.crypto.tink.internal.Util;
import java.util.HashSet;
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
  }

  @BeforeClass
  public static void registerTink() throws Exception {
    TinkConfig.register();
  }

  @DataPoints("EquivalentPairs")
  public static final Pair[] TEMPLATES =
      new Pair[] {
        new Pair("AES128_GCM", PredefinedAeadParameters.AES128_GCM),
        new Pair("AES256_GCM", PredefinedAeadParameters.AES256_GCM)
      };

  @Theory
  public void testParametersEqualsKeyTemplate(@FromDataPoints("EquivalentPairs") Pair p)
      throws Exception {
    assertThat(KeyTemplates.get(p.templateName).toParameters()).isEqualTo(p.parameters);
  }

  private static Set<String> getAllTestedNames() {
    Set<String> result = new HashSet<>();
    for (Pair p : TEMPLATES) {
      result.add(p.templateName);
    }
    return result;
  }

  private static Set<String> getUntestedNames() {
    Set<String> result = new HashSet<>();
    result.add("AES128_CTR_HMAC_SHA256");
    result.add("AES128_CTR_HMAC_SHA256_1MB");
    result.add("AES128_CTR_HMAC_SHA256_4KB");
    result.add("AES128_CTR_HMAC_SHA256_RAW");
    result.add("AES128_EAX");
    result.add("AES128_EAX_RAW");
    result.add("AES128_GCM_HKDF_1MB");
    result.add("AES128_GCM_HKDF_4KB");
    result.add("AES128_GCM_RAW");
    result.add("AES256_CMAC");
    result.add("AES256_CMAC_PRF");
    result.add("AES256_CMAC_RAW");
    result.add("AES256_CTR_HMAC_SHA256");
    result.add("AES256_CTR_HMAC_SHA256_1MB");
    result.add("AES256_CTR_HMAC_SHA256_4KB");
    result.add("AES256_CTR_HMAC_SHA256_RAW");
    result.add("AES256_EAX");
    result.add("AES256_EAX_RAW");
    result.add("AES256_GCM_HKDF_1MB");
    result.add("AES256_GCM_HKDF_4KB");
    result.add("AES256_GCM_RAW");
    result.add("AES256_SIV");
    result.add("AES256_SIV_RAW");
    result.add("AES_CMAC");
    result.add("AES_CMAC_PRF");
    result.add("CHACHA20_POLY1305");
    result.add("CHACHA20_POLY1305_RAW");
    result.add("DHKEM_P256_HKDF_SHA256_HKDF_SHA256_AES_128_GCM");
    result.add("DHKEM_P256_HKDF_SHA256_HKDF_SHA256_AES_128_GCM_RAW");
    result.add("DHKEM_P256_HKDF_SHA256_HKDF_SHA256_AES_256_GCM");
    result.add("DHKEM_P256_HKDF_SHA256_HKDF_SHA256_AES_256_GCM_RAW");
    result.add("DHKEM_P384_HKDF_SHA384_HKDF_SHA384_AES_128_GCM");
    result.add("DHKEM_P384_HKDF_SHA384_HKDF_SHA384_AES_128_GCM_RAW");
    result.add("DHKEM_P384_HKDF_SHA384_HKDF_SHA384_AES_256_GCM");
    result.add("DHKEM_P384_HKDF_SHA384_HKDF_SHA384_AES_256_GCM_RAW");
    result.add("DHKEM_P521_HKDF_SHA512_HKDF_SHA512_AES_128_GCM");
    result.add("DHKEM_P521_HKDF_SHA512_HKDF_SHA512_AES_128_GCM_RAW");
    result.add("DHKEM_P521_HKDF_SHA512_HKDF_SHA512_AES_256_GCM");
    result.add("DHKEM_P521_HKDF_SHA512_HKDF_SHA512_AES_256_GCM_RAW");
    result.add("DHKEM_X25519_HKDF_SHA256_HKDF_SHA256_AES_128_GCM");
    result.add("DHKEM_X25519_HKDF_SHA256_HKDF_SHA256_AES_128_GCM_RAW");
    result.add("DHKEM_X25519_HKDF_SHA256_HKDF_SHA256_AES_256_GCM");
    result.add("DHKEM_X25519_HKDF_SHA256_HKDF_SHA256_AES_256_GCM_RAW");
    result.add("DHKEM_X25519_HKDF_SHA256_HKDF_SHA256_CHACHA20_POLY1305");
    result.add("DHKEM_X25519_HKDF_SHA256_HKDF_SHA256_CHACHA20_POLY1305_RAW");
    result.add("ECDSA_P256");
    result.add("ECDSA_P256_IEEE_P1363");
    result.add("ECDSA_P256_IEEE_P1363_WITHOUT_PREFIX");
    result.add("ECDSA_P256_RAW");
    result.add("ECDSA_P384");
    result.add("ECDSA_P384_IEEE_P1363");
    result.add("ECDSA_P384_SHA384");
    result.add("ECDSA_P384_SHA512");
    result.add("ECDSA_P521");
    result.add("ECDSA_P521_IEEE_P1363");
    result.add("ECIES_P256_COMPRESSED_HKDF_HMAC_SHA256_AES128_CTR_HMAC_SHA256");
    result.add("ECIES_P256_COMPRESSED_HKDF_HMAC_SHA256_AES128_CTR_HMAC_SHA256_RAW");
    result.add("ECIES_P256_COMPRESSED_HKDF_HMAC_SHA256_AES128_GCM");
    result.add("ECIES_P256_COMPRESSED_HKDF_HMAC_SHA256_AES128_GCM_RAW");
    result.add("ECIES_P256_HKDF_HMAC_SHA256_AES128_CTR_HMAC_SHA256");
    result.add("ECIES_P256_HKDF_HMAC_SHA256_AES128_CTR_HMAC_SHA256_RAW");
    result.add("ECIES_P256_HKDF_HMAC_SHA256_AES128_GCM");
    result.add("ECIES_P256_HKDF_HMAC_SHA256_AES128_GCM_COMPRESSED_WITHOUT_PREFIX");
    result.add("ECIES_P256_HKDF_HMAC_SHA256_AES128_GCM_RAW");
    result.add("ED25519");
    result.add("ED25519_RAW");
    result.add("ED25519WithRawOutput");
    result.add("HKDF_SHA256");
    result.add("HMAC_SHA256_128BITTAG");
    result.add("HMAC_SHA256_128BITTAG_RAW");
    result.add("HMAC_SHA256_256BITTAG");
    result.add("HMAC_SHA256_256BITTAG_RAW");
    result.add("HMAC_SHA256_PRF");
    result.add("HMAC_SHA512_128BITTAG");
    result.add("HMAC_SHA512_128BITTAG_RAW");
    result.add("HMAC_SHA512_256BITTAG");
    result.add("HMAC_SHA512_256BITTAG_RAW");
    result.add("HMAC_SHA512_512BITTAG");
    result.add("HMAC_SHA512_512BITTAG_RAW");
    result.add("HMAC_SHA512_PRF");
    result.add("RSA_SSA_PKCS1_3072_SHA256_F4");
    result.add("RSA_SSA_PKCS1_3072_SHA256_F4_RAW");
    result.add("RSA_SSA_PKCS1_3072_SHA256_F4_WITHOUT_PREFIX");
    result.add("RSA_SSA_PKCS1_4096_SHA512_F4");
    result.add("RSA_SSA_PKCS1_4096_SHA512_F4_RAW");
    result.add("RSA_SSA_PSS_3072_SHA256_F4");
    result.add("RSA_SSA_PSS_3072_SHA256_F4_RAW");
    result.add("RSA_SSA_PSS_3072_SHA256_SHA256_32_F4");
    result.add("RSA_SSA_PSS_4096_SHA512_F4");
    result.add("RSA_SSA_PSS_4096_SHA512_F4_RAW");
    result.add("RSA_SSA_PSS_4096_SHA512_SHA512_64_F4");
    result.add("XCHACHA20_POLY1305");
    result.add("XCHACHA20_POLY1305_RAW");
    if (Util.isAndroid()) {
      result.add("AES128_GCM_SIV");
      result.add("AES128_GCM_SIV_RAW");
      result.add("AES256_GCM_SIV");
      result.add("AES256_GCM_SIV_RAW");
    }

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
