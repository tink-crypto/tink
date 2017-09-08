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

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import com.google.crypto.tink.Config;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.PublicKeySign;
import com.google.crypto.tink.PublicKeyVerify;
import com.google.crypto.tink.TestUtil;
import com.google.crypto.tink.proto.EcdsaKeyFormat;
import com.google.crypto.tink.proto.EcdsaParams;
import com.google.crypto.tink.proto.EcdsaPrivateKey;
import com.google.crypto.tink.proto.EcdsaPublicKey;
import com.google.crypto.tink.proto.EcdsaSignatureEncoding;
import com.google.crypto.tink.proto.EllipticCurveType;
import com.google.crypto.tink.proto.HashType;
import com.google.crypto.tink.proto.KeyData;
import com.google.crypto.tink.proto.KeyTemplate;
import com.google.crypto.tink.subtle.EllipticCurves;
import com.google.crypto.tink.subtle.Random;
import com.google.protobuf.ByteString;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.util.Set;
import java.util.TreeSet;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/**
 * Unit tests for EcdsaSignKeyManager.
 *
 * <p>TODO(quannguyen): Add more tests.
 */
@RunWith(JUnit4.class)
public class EcdsaSignKeyManagerTest {
  @BeforeClass
  public static void setUp() throws Exception {
    Config.register(SignatureConfig.TINK_1_0_0);
    ;
  }

  private static class HashAndCurveType {
    public HashType hashType;
    public EllipticCurveType curveType;

    public HashAndCurveType(HashType hashType, EllipticCurveType curveType) {
      this.hashType = hashType;
      this.curveType = curveType;
    }
  }

  final byte[] msg = Random.randBytes(1281);

  @Test
  public void testNewKeyWithVerifier() throws Exception {
    KeyTemplate[] keyTemplates =
        new KeyTemplate[] {
          SignatureKeyTemplates.ECDSA_P256,
          SignatureKeyTemplates.ECDSA_P384,
          SignatureKeyTemplates.ECDSA_P521
        };
    for (int i = 0; i < keyTemplates.length; i++) {
      // Call newKey multiple times and make sure that it generates different keys.
      int numTests = 27;
      EcdsaPrivateKey[] privKeys = new EcdsaPrivateKey[numTests];
      EcdsaSignKeyManager signManager = new EcdsaSignKeyManager();
      Set<String> keys = new TreeSet<String>();
      for (int j = 0; j < numTests / 3; j++) {
        privKeys[3 * j] =
            (EcdsaPrivateKey)
                signManager.newKey(EcdsaKeyFormat.parseFrom(keyTemplates[i].getValue()));
        privKeys[3 * j + 1] = (EcdsaPrivateKey) signManager.newKey(keyTemplates[i].getValue());
        privKeys[3 * j + 2] =
            EcdsaPrivateKey.parseFrom(
                signManager.newKeyData(keyTemplates[i].getValue()).getValue());
        keys.add(TestUtil.hexEncode(privKeys[3 * j].toByteArray()));
        keys.add(TestUtil.hexEncode(privKeys[3 * j + 1].toByteArray()));
        keys.add(TestUtil.hexEncode(privKeys[3 * j + 2].toByteArray()));
      }
      assertEquals(numTests, keys.size());
      // Tests that generated keys have an adequate size. This is best-effort because keys might
      // have leading zeros that are stripped off. These tests are flaky; the probability of
      // failure is 2^-64 which happens when a key has 8 leading zeros.
      for (int j = 0; j < numTests; j++) {
        int keySize = privKeys[j].getKeyValue().toByteArray().length;
        EcdsaKeyFormat ecdsaKeyFormat = EcdsaKeyFormat.parseFrom(keyTemplates[i].getValue());
        switch (ecdsaKeyFormat.getParams().getCurve()) {
          case NIST_P256:
            assertTrue(256 / 8 - 8 <= keySize);
            assertTrue(256 / 8 + 1 >= keySize);
            break;
          case NIST_P384:
            assertTrue(384 / 8 - 8 <= keySize);
            assertTrue(384 / 8 + 1 >= keySize);
            break;
          case NIST_P521:
            assertTrue(521 / 8 - 8 <= keySize);
            assertTrue(521 / 8 + 1 >= keySize);
            break;
          default:
            break;
        }
      }

      // Test whether signer works correctly with the corresponding verifier.
      EcdsaVerifyKeyManager verifyManager = new EcdsaVerifyKeyManager();
      for (int j = 0; j < numTests; j++) {
        PublicKeySign signer = signManager.getPrimitive(privKeys[j]);
        byte[] signature = signer.sign(msg);
        for (int k = 0; k < numTests; k++) {
          PublicKeyVerify verifier = verifyManager.getPrimitive(privKeys[k].getPublicKey());
          if (j == k) { // The same key
            try {
              verifier.verify(signature, msg);
            } catch (GeneralSecurityException ex) {
              fail("Valid signature, should not throw exception");
            }
          } else { // Different keys
            try {
              verifier.verify(signature, msg);
              fail("Invalid signature, should have thrown exception");
            } catch (GeneralSecurityException expected) {
              // Expected
            }
          }
        }
      }
    }
  }

  @Test
  public void testNewKeyWithCorruptedFormat() {
    ByteString serialized = ByteString.copyFrom(new byte[128]);
    KeyTemplate keyTemplate =
        KeyTemplate.newBuilder()
            .setTypeUrl(EcdsaSignKeyManager.TYPE_URL)
            .setValue(serialized)
            .build();
    EcdsaSignKeyManager keyManager = new EcdsaSignKeyManager();
    try {
      keyManager.newKey(serialized);
      fail("Corrupted format, should have thrown exception");
    } catch (GeneralSecurityException expected) {
      // Expected
    }
    try {
      keyManager.newKeyData(keyTemplate.getValue());
      fail("Corrupted format, should have thrown exception");
    } catch (GeneralSecurityException expected) {
      // Expected
    }
  }

  @Test
  public void testNewKeyUnsupportedEncoding() throws Exception {
    EcdsaSignKeyManager signManager = new EcdsaSignKeyManager();
    EcdsaParams ecdsaParams =
        EcdsaParams.newBuilder()
            .setHashType(HashType.SHA256)
            .setCurve(EllipticCurveType.NIST_P256)
            .setEncoding(EcdsaSignatureEncoding.IEEE_P1363)
            .build();
    EcdsaKeyFormat ecdsaFormat = EcdsaKeyFormat.newBuilder().setParams(ecdsaParams).build();
    try {
      signManager.newKey(ecdsaFormat);
      fail("Unsupported encoding, should have thrown exception");
    } catch (GeneralSecurityException expecpted) {
      // Raw encoding is not supported yet.
    }
  }

  @Test
  public void testNewKeyUnsupportedKeyFormat() throws Exception {
    HashAndCurveType[] hashAndCurves = {
      new HashAndCurveType(HashType.SHA1, EllipticCurveType.NIST_P256),
      new HashAndCurveType(HashType.SHA1, EllipticCurveType.NIST_P384),
      new HashAndCurveType(HashType.SHA1, EllipticCurveType.NIST_P521),
      new HashAndCurveType(HashType.SHA256, EllipticCurveType.NIST_P384),
      new HashAndCurveType(HashType.SHA256, EllipticCurveType.NIST_P521),
      new HashAndCurveType(HashType.SHA512, EllipticCurveType.NIST_P256),
    };
    for (int i = 0; i < hashAndCurves.length; i++) {
      HashType hashType = hashAndCurves[i].hashType;
      EllipticCurveType curveType = hashAndCurves[i].curveType;
      EcdsaSignKeyManager signManager = new EcdsaSignKeyManager();
      EcdsaParams ecdsaParams =
          EcdsaParams.newBuilder()
              .setHashType(hashType)
              .setCurve(curveType)
              .setEncoding(EcdsaSignatureEncoding.DER)
              .build();
      EcdsaKeyFormat ecdsaFormat = EcdsaKeyFormat.newBuilder().setParams(ecdsaParams).build();
      try {
        EcdsaPrivateKey unusedPrivKey = (EcdsaPrivateKey) signManager.newKey(ecdsaFormat);
        fail("Unsupported key format, should have thrown exception: " + hashType + " " + curveType);
      } catch (GeneralSecurityException expected) {
        // Expected
      }
    }
  }

  @Test
  public void testGetPrimitiveWithVerifier() throws Exception {
    HashAndCurveType[] hashAndCurves = {
      new HashAndCurveType(HashType.SHA256, EllipticCurveType.NIST_P256),
      new HashAndCurveType(HashType.SHA512, EllipticCurveType.NIST_P384),
      new HashAndCurveType(HashType.SHA512, EllipticCurveType.NIST_P521)
    };
    for (int i = 0; i < hashAndCurves.length; i++) {
      HashType hashType = hashAndCurves[i].hashType;
      EllipticCurveType curveType = hashAndCurves[i].curveType;
      ECParameterSpec ecParams = EllipticCurves.getCurveSpec(SigUtil.toCurveType(curveType));
      KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC");
      keyGen.initialize(ecParams);
      KeyPair keyPair = keyGen.generateKeyPair();
      ECPublicKey pubKey = (ECPublicKey) keyPair.getPublic();
      ECPrivateKey privKey = (ECPrivateKey) keyPair.getPrivate();

      ECPoint w = pubKey.getW();
      EcdsaPublicKey ecdsaPubKey =
          TestUtil.createEcdsaPubKey(
              hashType,
              curveType,
              EcdsaSignatureEncoding.DER,
              w.getAffineX().toByteArray(),
              w.getAffineY().toByteArray());
      EcdsaPrivateKey ecdsaPrivKey =
          TestUtil.createEcdsaPrivKey(ecdsaPubKey, privKey.getS().toByteArray());
      EcdsaSignKeyManager signManager = new EcdsaSignKeyManager();
      PublicKeySign signer = signManager.getPrimitive(ecdsaPrivKey);
      PublicKeyVerify verifier = (new EcdsaVerifyKeyManager()).getPrimitive(ecdsaPubKey);
      try {
        verifier.verify(signer.sign(msg), msg);
      } catch (GeneralSecurityException e) {
        fail("Valid signature, should not throw exception");
      }
    }
  }

  @Test
  public void testGetPrimitiveWithUnsupportedKey() throws Exception {
    HashAndCurveType[] hashAndCurves = {
      new HashAndCurveType(HashType.SHA1, EllipticCurveType.NIST_P256),
      new HashAndCurveType(HashType.SHA1, EllipticCurveType.NIST_P384),
      new HashAndCurveType(HashType.SHA1, EllipticCurveType.NIST_P521),
      new HashAndCurveType(HashType.SHA256, EllipticCurveType.NIST_P384),
      new HashAndCurveType(HashType.SHA256, EllipticCurveType.NIST_P521),
      new HashAndCurveType(HashType.SHA512, EllipticCurveType.NIST_P256),
    };
    for (int i = 0; i < hashAndCurves.length; i++) {
      HashType hashType = hashAndCurves[i].hashType;
      EllipticCurveType curveType = hashAndCurves[i].curveType;
      ECParameterSpec ecParams = EllipticCurves.getCurveSpec(SigUtil.toCurveType(curveType));
      KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC");
      keyGen.initialize(ecParams);
      KeyPair keyPair = keyGen.generateKeyPair();
      ECPublicKey pubKey = (ECPublicKey) keyPair.getPublic();
      ECPrivateKey privKey = (ECPrivateKey) keyPair.getPrivate();

      ECPoint w = pubKey.getW();
      EcdsaPublicKey ecdsaPubKey =
          TestUtil.createEcdsaPubKey(
              hashType,
              curveType,
              EcdsaSignatureEncoding.DER,
              w.getAffineX().toByteArray(),
              w.getAffineY().toByteArray());
      EcdsaPrivateKey ecdsaPrivKey =
          TestUtil.createEcdsaPrivKey(ecdsaPubKey, privKey.getS().toByteArray());

      EcdsaSignKeyManager signManager = new EcdsaSignKeyManager();
      try {
        PublicKeySign unusedSigner = signManager.getPrimitive(ecdsaPrivKey);
        fail("Unsupported key, should have thrown exception: " + hashType + " " + curveType);
      } catch (GeneralSecurityException expected) {
        // Expected
      }
    }
  }

  /** Tests that a public key is extracted properly from a private key. */
  @Test
  public void testGetPublicKeyData() throws Exception {
    KeysetHandle privateHandle = KeysetHandle.generateNew(SignatureKeyTemplates.ECDSA_P256);
    KeyData privateKeyData = TestUtil.getKeyset(privateHandle).getKey(0).getKeyData();
    EcdsaSignKeyManager privateManager = new EcdsaSignKeyManager();
    KeyData publicKeyData = privateManager.getPublicKeyData(privateKeyData.getValue());
    assertEquals(EcdsaVerifyKeyManager.TYPE_URL, publicKeyData.getTypeUrl());
    assertEquals(KeyData.KeyMaterialType.ASYMMETRIC_PUBLIC, publicKeyData.getKeyMaterialType());
    EcdsaPrivateKey privateKey = EcdsaPrivateKey.parseFrom(privateKeyData.getValue());
    assertArrayEquals(
        privateKey.getPublicKey().toByteArray(), publicKeyData.getValue().toByteArray());

    EcdsaVerifyKeyManager publicManager = new EcdsaVerifyKeyManager();
    PublicKeySign signer = privateManager.getPrimitive(privateKeyData.getValue());
    PublicKeyVerify verifier = publicManager.getPrimitive(publicKeyData.getValue());
    byte[] message = Random.randBytes(20);
    try {
      verifier.verify(signer.sign(message), message);
    } catch (GeneralSecurityException e) {
      fail("Should not fail: " + e);
    }
  }
}
