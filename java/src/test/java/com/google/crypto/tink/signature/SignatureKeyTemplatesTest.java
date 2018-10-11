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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import com.google.crypto.tink.proto.EcdsaKeyFormat;
import com.google.crypto.tink.proto.EcdsaSignatureEncoding;
import com.google.crypto.tink.proto.EllipticCurveType;
import com.google.crypto.tink.proto.HashType;
import com.google.crypto.tink.proto.KeyTemplate;
import com.google.crypto.tink.proto.OutputPrefixType;
import com.google.crypto.tink.proto.RsaSsaPkcs1KeyFormat;
import com.google.crypto.tink.proto.RsaSsaPssKeyFormat;
import java.math.BigInteger;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Tests for SignatureKeyTemplates. */
@RunWith(JUnit4.class)
public class SignatureKeyTemplatesTest {
  @Test
  public void testECDSA_P256() throws Exception {
    KeyTemplate template = SignatureKeyTemplates.ECDSA_P256;
    assertEquals(EcdsaSignKeyManager.TYPE_URL, template.getTypeUrl());
    assertEquals(OutputPrefixType.TINK, template.getOutputPrefixType());
    EcdsaKeyFormat format = EcdsaKeyFormat.parseFrom(template.getValue());

    assertTrue(format.hasParams());
    assertEquals(HashType.SHA256, format.getParams().getHashType());
    assertEquals(EllipticCurveType.NIST_P256, format.getParams().getCurve());
    assertEquals(EcdsaSignatureEncoding.DER, format.getParams().getEncoding());
  }

  @Test
  public void testECDSA_P256_IEEE_P1363() throws Exception {
    KeyTemplate template = SignatureKeyTemplates.ECDSA_P256_IEEE_P1363;
    assertEquals(EcdsaSignKeyManager.TYPE_URL, template.getTypeUrl());
    assertEquals(OutputPrefixType.TINK, template.getOutputPrefixType());
    EcdsaKeyFormat format = EcdsaKeyFormat.parseFrom(template.getValue());

    assertTrue(format.hasParams());
    assertEquals(HashType.SHA256, format.getParams().getHashType());
    assertEquals(EllipticCurveType.NIST_P256, format.getParams().getCurve());
    assertEquals(EcdsaSignatureEncoding.IEEE_P1363, format.getParams().getEncoding());
  }

  @Test
  public void testECDSA_P384() throws Exception {
    KeyTemplate template = SignatureKeyTemplates.ECDSA_P384;
    assertEquals(EcdsaSignKeyManager.TYPE_URL, template.getTypeUrl());
    assertEquals(OutputPrefixType.TINK, template.getOutputPrefixType());
    EcdsaKeyFormat format = EcdsaKeyFormat.parseFrom(template.getValue());

    assertTrue(format.hasParams());
    assertEquals(HashType.SHA512, format.getParams().getHashType());
    assertEquals(EllipticCurveType.NIST_P384, format.getParams().getCurve());
    assertEquals(EcdsaSignatureEncoding.DER, format.getParams().getEncoding());
  }

  @Test
  public void testECDSA_P384_IEEE_P1363() throws Exception {
    KeyTemplate template = SignatureKeyTemplates.ECDSA_P384_IEEE_P1363;
    assertEquals(EcdsaSignKeyManager.TYPE_URL, template.getTypeUrl());
    assertEquals(OutputPrefixType.TINK, template.getOutputPrefixType());
    EcdsaKeyFormat format = EcdsaKeyFormat.parseFrom(template.getValue());

    assertTrue(format.hasParams());
    assertEquals(HashType.SHA512, format.getParams().getHashType());
    assertEquals(EllipticCurveType.NIST_P384, format.getParams().getCurve());
    assertEquals(EcdsaSignatureEncoding.IEEE_P1363, format.getParams().getEncoding());
  }

  @Test
  public void testECDSA_P521_IEEE_P1363() throws Exception {
    KeyTemplate template = SignatureKeyTemplates.ECDSA_P521_IEEE_P1363;
    assertEquals(EcdsaSignKeyManager.TYPE_URL, template.getTypeUrl());
    assertEquals(OutputPrefixType.TINK, template.getOutputPrefixType());
    EcdsaKeyFormat format = EcdsaKeyFormat.parseFrom(template.getValue());

    assertTrue(format.hasParams());
    assertEquals(HashType.SHA512, format.getParams().getHashType());
    assertEquals(EllipticCurveType.NIST_P521, format.getParams().getCurve());
    assertEquals(EcdsaSignatureEncoding.IEEE_P1363, format.getParams().getEncoding());
  }

  @Test
  public void testCreateEcdsaKeyTemplate() throws Exception {
    // Intentionally using "weird" or invalid values for parameters,
    // to test that the function correctly puts them in the resulting template.
    HashType hashType = HashType.SHA512;
    EllipticCurveType curve = EllipticCurveType.UNKNOWN_CURVE;
    EcdsaSignatureEncoding encoding = EcdsaSignatureEncoding.IEEE_P1363;
    KeyTemplate template = SignatureKeyTemplates.createEcdsaKeyTemplate(hashType, curve, encoding);
    assertEquals(EcdsaSignKeyManager.TYPE_URL, template.getTypeUrl());
    assertEquals(OutputPrefixType.TINK, template.getOutputPrefixType());

    EcdsaKeyFormat format = EcdsaKeyFormat.parseFrom(template.getValue());
    assertEquals(hashType, format.getParams().getHashType());
    assertEquals(curve, format.getParams().getCurve());
    assertEquals(encoding, format.getParams().getEncoding());
  }

  @Test
  public void testED25519() throws Exception {
    KeyTemplate template = SignatureKeyTemplates.ED25519;
    assertEquals(Ed25519PrivateKeyManager.TYPE_URL, template.getTypeUrl());
    assertEquals(OutputPrefixType.TINK, template.getOutputPrefixType());
    assertTrue(template.getValue().isEmpty()); // Empty format.
  }

  @Test
  public void testRSA_SSA_PKCS1_3072_SHA256_F4() throws Exception {
    KeyTemplate template = SignatureKeyTemplates.RSA_SSA_PKCS1_3072_SHA256_F4;
    assertEquals(RsaSsaPkcs1SignKeyManager.TYPE_URL, template.getTypeUrl());
    assertEquals(OutputPrefixType.TINK, template.getOutputPrefixType());
    RsaSsaPkcs1KeyFormat format = RsaSsaPkcs1KeyFormat.parseFrom(template.getValue());

    assertTrue(format.hasParams());
    assertEquals(HashType.SHA256, format.getParams().getHashType());
    assertEquals(3072, format.getModulusSizeInBits());
    assertEquals(
        BigInteger.valueOf(65537), new BigInteger(1, format.getPublicExponent().toByteArray()));
  }

  @Test
  public void testRSA_SSA_PKCS1_4096_SHA512_F4() throws Exception {
    KeyTemplate template = SignatureKeyTemplates.RSA_SSA_PKCS1_4096_SHA512_F4;
    assertEquals(RsaSsaPkcs1SignKeyManager.TYPE_URL, template.getTypeUrl());
    assertEquals(OutputPrefixType.TINK, template.getOutputPrefixType());
    RsaSsaPkcs1KeyFormat format = RsaSsaPkcs1KeyFormat.parseFrom(template.getValue());

    assertTrue(format.hasParams());
    assertEquals(HashType.SHA512, format.getParams().getHashType());
    assertEquals(4096, format.getModulusSizeInBits());
    assertEquals(
        BigInteger.valueOf(65537), new BigInteger(1, format.getPublicExponent().toByteArray()));
  }

  @Test
  public void testRSA_SSA_PSS_3072_SHA256_SHA256_32_F4() throws Exception {
    KeyTemplate template = SignatureKeyTemplates.RSA_SSA_PSS_3072_SHA256_SHA256_32_F4;
    assertEquals(RsaSsaPssSignKeyManager.TYPE_URL, template.getTypeUrl());
    assertEquals(OutputPrefixType.TINK, template.getOutputPrefixType());
    RsaSsaPssKeyFormat format = RsaSsaPssKeyFormat.parseFrom(template.getValue());

    assertTrue(format.hasParams());
    assertEquals(HashType.SHA256, format.getParams().getSigHash());
    assertEquals(HashType.SHA256, format.getParams().getMgf1Hash());
    assertEquals(32, format.getParams().getSaltLength());
    assertEquals(3072, format.getModulusSizeInBits());
    assertEquals(
        BigInteger.valueOf(65537), new BigInteger(1, format.getPublicExponent().toByteArray()));
  }

  @Test
  public void testRSA_SSA_PSS_4096_SHA512_SHA512_64_F4() throws Exception {
    KeyTemplate template = SignatureKeyTemplates.RSA_SSA_PSS_4096_SHA512_SHA512_64_F4;
    assertEquals(RsaSsaPssSignKeyManager.TYPE_URL, template.getTypeUrl());
    assertEquals(OutputPrefixType.TINK, template.getOutputPrefixType());
    RsaSsaPssKeyFormat format = RsaSsaPssKeyFormat.parseFrom(template.getValue());

    assertTrue(format.hasParams());
    assertEquals(HashType.SHA512, format.getParams().getSigHash());
    assertEquals(HashType.SHA512, format.getParams().getMgf1Hash());
    assertEquals(64, format.getParams().getSaltLength());
    assertEquals(4096, format.getModulusSizeInBits());
    assertEquals(
        BigInteger.valueOf(65537), new BigInteger(1, format.getPublicExponent().toByteArray()));
  }
}
