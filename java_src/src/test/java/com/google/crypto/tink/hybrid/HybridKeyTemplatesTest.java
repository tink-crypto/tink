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

package com.google.crypto.tink.hybrid;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import com.google.crypto.tink.aead.AeadKeyTemplates;
import com.google.crypto.tink.proto.EcPointFormat;
import com.google.crypto.tink.proto.EciesAeadHkdfKeyFormat;
import com.google.crypto.tink.proto.EciesHkdfKemParams;
import com.google.crypto.tink.proto.EllipticCurveType;
import com.google.crypto.tink.proto.HashType;
import com.google.crypto.tink.proto.KeyTemplate;
import com.google.crypto.tink.proto.OutputPrefixType;
import com.google.protobuf.ExtensionRegistryLite;
import java.nio.charset.Charset;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Tests for HybridKeyTemplates. */
@RunWith(JUnit4.class)
public class HybridKeyTemplatesTest {
  private static final Charset UTF_8 = Charset.forName("UTF-8");

  @Test
  public void eciesP256HkdfHmaSha256Aes128Gcm() throws Exception {
    KeyTemplate template = HybridKeyTemplates.ECIES_P256_HKDF_HMAC_SHA256_AES128_GCM;
    assertEquals(new EciesAeadHkdfPrivateKeyManager().getKeyType(), template.getTypeUrl());
    assertEquals(OutputPrefixType.TINK, template.getOutputPrefixType());
    EciesAeadHkdfKeyFormat format =
        EciesAeadHkdfKeyFormat.parseFrom(
            template.getValue(), ExtensionRegistryLite.getEmptyRegistry());

    assertTrue(format.hasParams());
    assertTrue(format.getParams().hasKemParams());
    assertTrue(format.getParams().hasDemParams());
    assertTrue(format.getParams().getDemParams().hasAeadDem());
    assertEquals(EcPointFormat.UNCOMPRESSED, format.getParams().getEcPointFormat());
    EciesHkdfKemParams kemParams = format.getParams().getKemParams();
    assertEquals(EllipticCurveType.NIST_P256, kemParams.getCurveType());
    assertEquals(HashType.SHA256, kemParams.getHkdfHashType());
    assertTrue(kemParams.getHkdfSalt().isEmpty());
    assertEquals(AeadKeyTemplates.AES128_GCM.toString(),
        format.getParams().getDemParams().getAeadDem().toString());
  }

  @Test
  public void eciesP256HkdfHmacSha256Aes128GcmCompressedWithoutPrefix() throws Exception {
    KeyTemplate template =
        HybridKeyTemplates.ECIES_P256_HKDF_HMAC_SHA256_AES128_GCM_COMPRESSED_WITHOUT_PREFIX;
    assertEquals(new EciesAeadHkdfPrivateKeyManager().getKeyType(), template.getTypeUrl());
    assertEquals(OutputPrefixType.RAW, template.getOutputPrefixType());
    EciesAeadHkdfKeyFormat format =
        EciesAeadHkdfKeyFormat.parseFrom(
            template.getValue(), ExtensionRegistryLite.getEmptyRegistry());

    assertTrue(format.hasParams());
    assertTrue(format.getParams().hasKemParams());
    assertTrue(format.getParams().hasDemParams());
    assertTrue(format.getParams().getDemParams().hasAeadDem());
    assertEquals(EcPointFormat.COMPRESSED, format.getParams().getEcPointFormat());
    EciesHkdfKemParams kemParams = format.getParams().getKemParams();
    assertEquals(EllipticCurveType.NIST_P256, kemParams.getCurveType());
    assertEquals(HashType.SHA256, kemParams.getHkdfHashType());
    assertTrue(kemParams.getHkdfSalt().isEmpty());
    assertEquals(AeadKeyTemplates.AES128_GCM.toString(),
        format.getParams().getDemParams().getAeadDem().toString());
  }

  @Test
  public void eciesP256HkdfHmacSha256Aes128CtrHmacSha256() throws Exception {
    KeyTemplate template = HybridKeyTemplates.ECIES_P256_HKDF_HMAC_SHA256_AES128_CTR_HMAC_SHA256;
    assertEquals(new EciesAeadHkdfPrivateKeyManager().getKeyType(), template.getTypeUrl());
    assertEquals(OutputPrefixType.TINK, template.getOutputPrefixType());
    EciesAeadHkdfKeyFormat format =
        EciesAeadHkdfKeyFormat.parseFrom(
            template.getValue(), ExtensionRegistryLite.getEmptyRegistry());

    assertTrue(format.hasParams());
    assertTrue(format.getParams().hasKemParams());
    assertTrue(format.getParams().hasDemParams());
    assertTrue(format.getParams().getDemParams().hasAeadDem());
    assertEquals(EcPointFormat.UNCOMPRESSED, format.getParams().getEcPointFormat());
    EciesHkdfKemParams kemParams = format.getParams().getKemParams();
    assertEquals(EllipticCurveType.NIST_P256, kemParams.getCurveType());
    assertEquals(HashType.SHA256, kemParams.getHkdfHashType());
    assertTrue(kemParams.getHkdfSalt().isEmpty());
    assertEquals(AeadKeyTemplates.AES128_CTR_HMAC_SHA256.toString(),
        format.getParams().getDemParams().getAeadDem().toString());
  }

  @Test
  public void testCreateEciesAeadHkdfKeyTemplate() throws Exception {
    // Intentionally using "weird" or invalid values for parameters,
    // to test that the function correctly puts them in the resulting template.
    EllipticCurveType curveType = EllipticCurveType.NIST_P384;
    HashType hashType = HashType.SHA512;
    EcPointFormat ecPointFormat = EcPointFormat.COMPRESSED;
    KeyTemplate demKeyTemplate = AeadKeyTemplates.AES256_EAX;
    String salt = "some salt";
    KeyTemplate template = HybridKeyTemplates.createEciesAeadHkdfKeyTemplate(
        curveType, hashType, ecPointFormat, demKeyTemplate,
        OutputPrefixType.TINK, salt.getBytes(UTF_8));
    assertEquals(new EciesAeadHkdfPrivateKeyManager().getKeyType(), template.getTypeUrl());
    assertEquals(OutputPrefixType.TINK, template.getOutputPrefixType());
    EciesAeadHkdfKeyFormat format =
        EciesAeadHkdfKeyFormat.parseFrom(
            template.getValue(), ExtensionRegistryLite.getEmptyRegistry());

    assertTrue(format.hasParams());
    assertTrue(format.getParams().hasKemParams());
    assertTrue(format.getParams().hasDemParams());
    assertTrue(format.getParams().getDemParams().hasAeadDem());
    assertEquals(ecPointFormat, format.getParams().getEcPointFormat());
    EciesHkdfKemParams kemParams = format.getParams().getKemParams();
    assertEquals(curveType, kemParams.getCurveType());
    assertEquals(hashType, kemParams.getHkdfHashType());
    assertEquals(salt, kemParams.getHkdfSalt().toStringUtf8());
    assertEquals(AeadKeyTemplates.AES256_EAX.toString(),
        format.getParams().getDemParams().getAeadDem().toString());
  }
}
