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

import static org.junit.Assert.assertThrows;

import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.PublicKeySign;
import com.google.crypto.tink.PublicKeyVerify;
import com.google.crypto.tink.proto.EcdsaPrivateKey;
import com.google.crypto.tink.proto.EcdsaSignatureEncoding;
import com.google.crypto.tink.proto.EllipticCurveType;
import com.google.crypto.tink.proto.HashType;
import com.google.crypto.tink.proto.KeyData;
import com.google.crypto.tink.proto.KeyStatusType;
import com.google.crypto.tink.proto.Keyset.Key;
import com.google.crypto.tink.proto.OutputPrefixType;
import com.google.crypto.tink.subtle.Random;
import com.google.crypto.tink.testing.TestUtil;
import java.security.GeneralSecurityException;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Tests which run the everything for the Public Key signing primitives. */
@RunWith(JUnit4.class)
// TODO(quannguyen): Add more tests.
public class PublicKeyVerifyIntegrationTest {

  @Before
  public void setUp() throws Exception {
    SignatureConfig.register();
  }

  @Test
  public void testMultipleKeys() throws Exception {
    EcdsaPrivateKey tinkPrivateKey =
        TestUtil.generateEcdsaPrivKey(
            EllipticCurveType.NIST_P521, HashType.SHA512, EcdsaSignatureEncoding.DER);
    Key tink =
        TestUtil.createKey(
            TestUtil.createKeyData(
                tinkPrivateKey.getPublicKey(),
                new EcdsaVerifyKeyManager().getKeyType(),
                KeyData.KeyMaterialType.ASYMMETRIC_PUBLIC),
            1,
            KeyStatusType.ENABLED,
            OutputPrefixType.TINK);

    EcdsaPrivateKey legacyPrivateKey =
        TestUtil.generateEcdsaPrivKey(
            EllipticCurveType.NIST_P256, HashType.SHA256, EcdsaSignatureEncoding.DER);
    Key legacy =
        TestUtil.createKey(
            TestUtil.createKeyData(
                legacyPrivateKey.getPublicKey(),
                new EcdsaVerifyKeyManager().getKeyType(),
                KeyData.KeyMaterialType.ASYMMETRIC_PUBLIC),
            2,
            KeyStatusType.ENABLED,
            OutputPrefixType.LEGACY);

    EcdsaPrivateKey rawPrivateKey =
        TestUtil.generateEcdsaPrivKey(
            EllipticCurveType.NIST_P384, HashType.SHA512, EcdsaSignatureEncoding.DER);
    Key raw =
        TestUtil.createKey(
            TestUtil.createKeyData(
                rawPrivateKey.getPublicKey(),
                new EcdsaVerifyKeyManager().getKeyType(),
                KeyData.KeyMaterialType.ASYMMETRIC_PUBLIC),
            3,
            KeyStatusType.ENABLED,
            OutputPrefixType.RAW);

    EcdsaPrivateKey crunchyPrivateKey =
        TestUtil.generateEcdsaPrivKey(
            EllipticCurveType.NIST_P384, HashType.SHA512, EcdsaSignatureEncoding.DER);
    Key crunchy =
        TestUtil.createKey(
            TestUtil.createKeyData(
                crunchyPrivateKey.getPublicKey(),
                new EcdsaVerifyKeyManager().getKeyType(),
                KeyData.KeyMaterialType.ASYMMETRIC_PUBLIC),
            4,
            KeyStatusType.ENABLED,
            OutputPrefixType.CRUNCHY);

    Key[] keys = new Key[] {tink, legacy, raw, crunchy};
    EcdsaPrivateKey[] privateKeys =
        new EcdsaPrivateKey[] {tinkPrivateKey, legacyPrivateKey, rawPrivateKey, crunchyPrivateKey};

    int j = keys.length;
    for (int i = 0; i < j; i++) {
      KeysetHandle keysetHandle =
          TestUtil.createKeysetHandle(
              TestUtil.createKeyset(
                  keys[i], keys[(i + 1) % j], keys[(i + 2) % j], keys[(i + 3) % j]));
      PublicKeyVerify verifier = keysetHandle.getPrimitive(PublicKeyVerify.class);
      // Signature from any keys in the keyset should be valid.
      for (int k = 0; k < j; k++) {
        PublicKeySign signer =
            TestUtil.createKeysetHandle(
                    TestUtil.createKeyset(
                        TestUtil.createKey(
                            TestUtil.createKeyData(
                                privateKeys[k],
                                new EcdsaSignKeyManager().getKeyType(),
                                KeyData.KeyMaterialType.ASYMMETRIC_PRIVATE),
                            keys[k].getKeyId(),
                            KeyStatusType.ENABLED,
                            keys[k].getOutputPrefixType())))
                .getPrimitive(PublicKeySign.class);
        byte[] plaintext = Random.randBytes(1211);
        byte[] sig = signer.sign(plaintext);
        try {
          verifier.verify(sig, plaintext);
        } catch (GeneralSecurityException ex) {
          throw new AssertionError("Valid signature, should not throw exception: " + k, ex);
        }
      }

      // Signature from a random key should be invalid.
      EcdsaPrivateKey randomPrivKey =
          TestUtil.generateEcdsaPrivKey(
              EllipticCurveType.NIST_P521, HashType.SHA512, EcdsaSignatureEncoding.DER);
      PublicKeySign signer =
          TestUtil.createKeysetHandle(
                  TestUtil.createKeyset(
                      TestUtil.createKey(
                          TestUtil.createKeyData(
                              randomPrivKey,
                              new EcdsaSignKeyManager().getKeyType(),
                              KeyData.KeyMaterialType.ASYMMETRIC_PRIVATE),
                          1,
                          KeyStatusType.ENABLED,
                          keys[0].getOutputPrefixType())))
              .getPrimitive(PublicKeySign.class);
      byte[] plaintext = Random.randBytes(1211);
      byte[] sig = signer.sign(plaintext);
      assertThrows(GeneralSecurityException.class, () -> verifier.verify(sig, plaintext));
    }
  }
}
