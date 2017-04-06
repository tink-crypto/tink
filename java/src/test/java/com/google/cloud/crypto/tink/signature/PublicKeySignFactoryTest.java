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

package com.google.cloud.crypto.tink.signature;

import static junit.framework.Assert.fail;
import static org.junit.Assert.assertArrayEquals;

import com.google.cloud.crypto.tink.CommonProto.EllipticCurveType;
import com.google.cloud.crypto.tink.CommonProto.HashType;
import com.google.cloud.crypto.tink.CryptoFormat;
import com.google.cloud.crypto.tink.EcdsaProto.EcdsaPrivateKey;
import com.google.cloud.crypto.tink.EcdsaProto.EcdsaSignatureEncoding;
import com.google.cloud.crypto.tink.KeysetHandle;
import com.google.cloud.crypto.tink.PublicKeySign;
import com.google.cloud.crypto.tink.PublicKeyVerify;
import com.google.cloud.crypto.tink.TestUtil;
import com.google.cloud.crypto.tink.TinkProto.KeyData;
import com.google.cloud.crypto.tink.TinkProto.KeyStatusType;
import com.google.cloud.crypto.tink.TinkProto.Keyset.Key;
import com.google.cloud.crypto.tink.TinkProto.OutputPrefixType;
import com.google.cloud.crypto.tink.subtle.Random;
import java.security.GeneralSecurityException;
import java.util.Arrays;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Unit tests for {@link PublicKeySignFactory}. */
@RunWith(JUnit4.class)
//TODO(quannguyen): Add more tests.
public class PublicKeySignFactoryTest {

  @Before
  public void setUp() throws Exception {
    PublicKeySignFactory.registerStandardKeyTypes();
    PublicKeyVerifyFactory.registerStandardKeyTypes();
  }

  @Test
  public void testMultipleKeys() throws Exception {
    // Permutations of {0, 1, 2}.
    int[][] ids = new int[][] {
      {0, 1, 2},
      {0, 2, 1},
      {1, 0, 2},
      {1, 2, 0},
      {2, 0, 1},
      {2, 1, 0}
    };
    EcdsaPrivateKey[] ecdsaPrivKeys = new EcdsaPrivateKey[] {
      TestUtil.generateEcdsaPrivKey(EllipticCurveType.NIST_P521, HashType.SHA512,
          EcdsaSignatureEncoding.DER),
      TestUtil.generateEcdsaPrivKey(EllipticCurveType.NIST_P384, HashType.SHA512,
          EcdsaSignatureEncoding.DER),
      TestUtil.generateEcdsaPrivKey(EllipticCurveType.NIST_P256, HashType.SHA256,
          EcdsaSignatureEncoding.DER)};
    Key[] keys = new Key[] {
      TestUtil.createKey(
          TestUtil.createKeyData(
              ecdsaPrivKeys[0],
              "type.googleapis.com/google.cloud.crypto.tink.EcdsaPrivateKey",
              KeyData.KeyMaterialType.ASYMMETRIC_PRIVATE),
          1,
          KeyStatusType.ENABLED,
          OutputPrefixType.TINK),
      TestUtil.createKey(
          TestUtil.createKeyData(
              ecdsaPrivKeys[1],
              "type.googleapis.com/google.cloud.crypto.tink.EcdsaPrivateKey",
              KeyData.KeyMaterialType.ASYMMETRIC_PRIVATE),
          2,
          KeyStatusType.ENABLED,
          OutputPrefixType.RAW),
      TestUtil.createKey(
          TestUtil.createKeyData(
              ecdsaPrivKeys[2],
              "type.googleapis.com/google.cloud.crypto.tink.EcdsaPrivateKey",
              KeyData.KeyMaterialType.ASYMMETRIC_PRIVATE),
          3,
          KeyStatusType.ENABLED,
          OutputPrefixType.LEGACY)};
    for (int i = 0; i < ids.length; i++) {
      KeysetHandle keysetHandle = TestUtil.createKeysetHandle(
        TestUtil.createKeyset(keys[ids[i][0]], keys[ids[i][1]], keys[ids[i][2]]));
      // Signs with the primary private key.
      PublicKeySign signer = PublicKeySignFactory.getPrimitive(keysetHandle);
      byte[] plaintext = Random.randBytes(1211);
      byte[] sig = signer.sign(plaintext);
      if (keys[ids[i][0]].getOutputPrefixType() != OutputPrefixType.RAW) {
        byte[] prefix = Arrays.copyOfRange(sig, 0, CryptoFormat.NON_RAW_PREFIX_SIZE);
        assertArrayEquals(prefix, CryptoFormat.getOutputPrefix(keys[ids[i][0]]));
      }

      // Verifying with the primary public key should work.
      PublicKeyVerify verifier = PublicKeyVerifyFactory.getPrimitive(
          TestUtil.createKeysetHandle(
              TestUtil.createKeyset(
                  TestUtil.createKey(
                      TestUtil.createKeyData(
                          ecdsaPrivKeys[ids[i][0]].getPublicKey(),
                          "type.googleapis.com/google.cloud.crypto.tink.EcdsaPublicKey",
                          KeyData.KeyMaterialType.ASYMMETRIC_PUBLIC),
                      ids[i][0] + 1,
                      KeyStatusType.ENABLED,
                      keys[ids[i][0]].getOutputPrefixType()))));
      try {
        verifier.verify(sig, plaintext);
      } catch (GeneralSecurityException ex) {
        fail("Valid signature, should not throw exception");
      }

      // Verifying with a non-primary public key should fail.
      verifier = PublicKeyVerifyFactory.getPrimitive(
          TestUtil.createKeysetHandle(
              TestUtil.createKeyset(
                  TestUtil.createKey(
                      TestUtil.createKeyData(
                          ecdsaPrivKeys[ids[i][1]].getPublicKey(),
                          "type.googleapis.com/google.cloud.crypto.tink.EcdsaPublicKey",
                          KeyData.KeyMaterialType.ASYMMETRIC_PUBLIC),
                      ids[i][1] + 1,
                      KeyStatusType.ENABLED,
                      keys[ids[i][1]].getOutputPrefixType()))));
      try {
        verifier.verify(sig, plaintext);
        fail("Invalid signature, should have thrown exception");
      } catch (GeneralSecurityException expected) {
      }
      // Verifying with a random public key should fail.
      EcdsaPrivateKey randomPrivKey = TestUtil.generateEcdsaPrivKey(
          EllipticCurveType.NIST_P521, HashType.SHA512, EcdsaSignatureEncoding.DER);
      verifier = PublicKeyVerifyFactory.getPrimitive(
          TestUtil.createKeysetHandle(
              TestUtil.createKeyset(
                  TestUtil.createKey(
                      TestUtil.createKeyData(
                          randomPrivKey.getPublicKey(),
                          "type.googleapis.com/google.cloud.crypto.tink.EcdsaPublicKey",
                          KeyData.KeyMaterialType.ASYMMETRIC_PUBLIC),
                      ids[i][0] + 1,
                      KeyStatusType.ENABLED,
                      keys[ids[i][0]].getOutputPrefixType()))));
      try {
        verifier.verify(sig, plaintext);
        fail("Invalid signature, should have thrown exception");
      } catch (GeneralSecurityException expected) {
        // Expected
      }
    }
  }
}
