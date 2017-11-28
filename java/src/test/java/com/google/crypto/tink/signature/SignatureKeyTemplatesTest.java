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
  public void testECDSA_P521() throws Exception {
    KeyTemplate template = SignatureKeyTemplates.ECDSA_P521;
    assertEquals(EcdsaSignKeyManager.TYPE_URL, template.getTypeUrl());
    assertEquals(OutputPrefixType.TINK, template.getOutputPrefixType());
    EcdsaKeyFormat format = EcdsaKeyFormat.parseFrom(template.getValue());

    assertTrue(format.hasParams());
    assertEquals(HashType.SHA512, format.getParams().getHashType());
    assertEquals(EllipticCurveType.NIST_P521, format.getParams().getCurve());
    assertEquals(EcdsaSignatureEncoding.DER, format.getParams().getEncoding());
  }

  @Test
  public void testCreateEcdsaKeyTemplate() throws Exception {
    // Intentionally using "weird" or invalid values for parameters,
    // to test that the function correctly puts them in the resulting template.
    HashType hashType = HashType.SHA512;
    EllipticCurveType curve = EllipticCurveType.NIST_P224;
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
    assertTrue(template.getValue().isEmpty());  // Empty format.
  }
}
