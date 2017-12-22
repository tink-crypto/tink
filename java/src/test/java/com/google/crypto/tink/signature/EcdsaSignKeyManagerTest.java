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

import static com.google.crypto.tink.TestUtil.assertExceptionContains;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import com.google.crypto.tink.Config;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.PublicKeySign;
import com.google.crypto.tink.PublicKeyVerify;
import com.google.crypto.tink.TestUtil;
import com.google.crypto.tink.Util;
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
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
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

  final byte[] msg = Random.randBytes(20);

  private void testNewKeyWithVerifier(KeyTemplate keyTemplate) throws Exception {
    // Call newKey multiple times and make sure that it generates different keys.
    int numTests = 9;
    EcdsaPrivateKey[] privKeys = new EcdsaPrivateKey[numTests];
    EcdsaSignKeyManager signManager = new EcdsaSignKeyManager();
    Set<String> keys = new TreeSet<String>();
    for (int j = 0; j < numTests / 3; j++) {
      privKeys[3 * j] =
          (EcdsaPrivateKey)
              signManager.newKey(EcdsaKeyFormat.parseFrom(keyTemplate.getValue()));
      keys.add(TestUtil.hexEncode(privKeys[3 * j].toByteArray()));

      privKeys[3 * j + 1] = (EcdsaPrivateKey) signManager.newKey(keyTemplate.getValue());
      keys.add(TestUtil.hexEncode(privKeys[3 * j + 1].toByteArray()));

      privKeys[3 * j + 2] =
          EcdsaPrivateKey.parseFrom(
              signManager.newKeyData(keyTemplate.getValue()).getValue());
      keys.add(TestUtil.hexEncode(privKeys[3 * j + 2].toByteArray()));
    }
    assertEquals(numTests, keys.size());

    // Tests that generated keys have an adequate size. This is best-effort because keys might
    // have leading zeros that are stripped off. These tests are flaky; the probability of
    // failure is 2^-64 which happens when a key has 8 leading zeros.
    for (int j = 0; j < numTests; j++) {
      int keySize = privKeys[j].getKeyValue().toByteArray().length;
      EcdsaKeyFormat ecdsaKeyFormat = EcdsaKeyFormat.parseFrom(keyTemplate.getValue());
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

  @Test
  public void testNewKeyWithVerifier() throws Exception {
    testNewKeyWithVerifier(SignatureKeyTemplates.ECDSA_P256);
    testNewKeyWithVerifier(SignatureKeyTemplates.ECDSA_P384);
    testNewKeyWithVerifier(SignatureKeyTemplates.ECDSA_P521);
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

  private void testNewKeyUnsupportedKeyFormat(HashAndCurveType hashAndCurve) throws Exception {
    HashType hashType = hashAndCurve.hashType;
    EllipticCurveType curveType = hashAndCurve.curveType;
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
      testNewKeyUnsupportedKeyFormat(hashAndCurves[i]);
    }
  }

  private void testGetPrimitiveWithUnsupportedKey(HashAndCurveType hashAndCurve) throws Exception {
    HashType hashType = hashAndCurve.hashType;
    EllipticCurveType curveType = hashAndCurve.curveType;
    KeyPair keyPair = EllipticCurves.generateKeyPair(SigUtil.toCurveType(curveType));
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
      testGetPrimitiveWithUnsupportedKey(hashAndCurves[i]);
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

  @Test
  public void testJsonExportAndImport() throws Exception {
    EcdsaSignKeyManager keyManager = new EcdsaSignKeyManager();
    int keyCount = 3;

    // Prepare example formats and keys.
    ByteString[] formats = new ByteString[keyCount];
    formats[0] = SignatureKeyTemplates.ECDSA_P256.getValue();
    formats[1] = SignatureKeyTemplates.ECDSA_P384.getValue();
    formats[2] = SignatureKeyTemplates.ECDSA_P521.getValue();

    EcdsaPrivateKey[] keys = new EcdsaPrivateKey[keyCount];
    for (int i = 0; i < keyCount; i++) {
      try {
        keys[i] = (EcdsaPrivateKey) keyManager.newKey(formats[i]);
      } catch (Exception e) {
        throw new Exception(e.toString() + "\nFailed for formats[" + i + "]:\n"
            + EcdsaKeyFormat.parseFrom(formats[i]).toString());
      }
    }

    // Check export and import of keys.
    int count = 0;
    for (EcdsaPrivateKey key : keys) {
      try {
        byte[] json = keyManager.keyToJson(key.toByteString());
        EcdsaPrivateKey keyFromJson = (EcdsaPrivateKey) keyManager.jsonToKey(json);
        assertEquals(key.toString(), keyFromJson.toString());
      } catch (Exception e) {
        throw new Exception(e.toString() + "\nFailed for key: " + key.toString());
      }
      count++;
    }
    assertEquals(keyCount, count);

    // Check export and import of key formats.
    count = 0;
    for (ByteString format : formats) {
      try {
        byte[] json = keyManager.keyFormatToJson(format);
        EcdsaKeyFormat formatFromJson = (EcdsaKeyFormat) keyManager.jsonToKeyFormat(json);
        assertEquals(EcdsaKeyFormat.parseFrom(format).toString(), formatFromJson.toString());
        count++;
      } catch (Exception e) {
        throw new Exception(e.toString() + "\nFailed for format:\n"
            + EcdsaKeyFormat.parseFrom(format).toString());
      }
    }
    assertEquals(keyCount, count);
  }

  @Test
  @SuppressWarnings("unused")  // Unused key/format/json-variables are not set unless test fails.
  public void testJsonExportAndImportErrors() throws Exception {
    EcdsaSignKeyManager keyManager = new EcdsaSignKeyManager();

    try {
      byte[] json = "some bad JSON key".getBytes(Util.UTF_8);
      EcdsaPrivateKey key = (EcdsaPrivateKey) keyManager.jsonToKey(json);
      fail("Corrupted JSON, should have thrown exception");
    } catch (GeneralSecurityException e) {
      // Expected.
      assertExceptionContains(e, "JSONException");
      assertExceptionContains(e, "text must begin");
    }

    try {
      byte[] json = "a bad JSON keyformat".getBytes(Util.UTF_8);
      EcdsaKeyFormat format = (EcdsaKeyFormat) keyManager.jsonToKeyFormat(json);
      fail("Corrupted JSON, should have thrown exception");
    } catch (GeneralSecurityException e) {
      // Expected.
      assertExceptionContains(e, "JSONException");
      assertExceptionContains(e, "text must begin");
    }

    try {  // An incomplete JSON key.
      byte[] json = "{\"version\": 0, \"keyValue\": \"some key bytes\"}".getBytes(Util.UTF_8);
      EcdsaPrivateKey key = (EcdsaPrivateKey) keyManager.jsonToKey(json);
      fail("Incomplet JSON key, should have thrown exception");
    } catch (GeneralSecurityException e) {
      // Expected.
      assertExceptionContains(e, "JSONException");
      assertExceptionContains(e, "Invalid key");
    }

    try {  // An incomplete JSON key format.
      byte[] json = "{}".getBytes(Util.UTF_8);
      EcdsaKeyFormat format = (EcdsaKeyFormat) keyManager.jsonToKeyFormat(json);
      fail("Incomplete JSON key format, should have thrown exception");
    } catch (GeneralSecurityException e) {
      // Expected.
      assertExceptionContains(e, "JSONException");
      assertExceptionContains(e, "Invalid key format");
    }

    try {  // Extra name in JSON key.
      byte[] json = ("{\"version\": 0, \"publicKey\": {}, "
          + "\"keyValue\": \"some key bytes\", \"extraName\": 42}").getBytes(Util.UTF_8);
      EcdsaPrivateKey key = (EcdsaPrivateKey) keyManager.jsonToKey(json);
      fail("Invalid JSON key, should have thrown exception");
    } catch (GeneralSecurityException e) {
      // Expected.
      assertExceptionContains(e, "JSONException");
      assertExceptionContains(e, "Invalid key");
    }

    try {  // Extra name JSON key format.
      byte[] json = ("{\"params\": {}, \"extraName\": 42}").getBytes(Util.UTF_8);
      EcdsaKeyFormat format = (EcdsaKeyFormat) keyManager.jsonToKeyFormat(json);
      fail("Invalid JSON key format, should have thrown exception");
    } catch (GeneralSecurityException e) {
      // Expected.
      assertExceptionContains(e, "JSONException");
      assertExceptionContains(e, "Invalid key format");
    }

    try {  // Incomplete public key in JSON key.
      byte[] json = ("{\"version\": 0, \"publicKey\": {\"params\": {}}, "
          + "\"keyValue\": \"some key bytes\"}").getBytes(Util.UTF_8);
      EcdsaPrivateKey key = (EcdsaPrivateKey) keyManager.jsonToKey(json);
      fail("Invalid JSON key, should have thrown exception");
    } catch (GeneralSecurityException e) {
      // Expected.
      assertExceptionContains(e, "JSONException");
      assertExceptionContains(e, "Invalid key");
    }

    try {  // An incomplete EcdsaPrivateKey.
      EcdsaPrivateKey key = EcdsaPrivateKey.newBuilder().setVersion(42).build();
      byte[] json = keyManager.keyToJson(key.toByteString());
      fail("Incomplete EcdsaPrivateKey, should have thrown exception");
    } catch (GeneralSecurityException e) {
      // Expected.
    }

    try {  // An incomplete EcdsaKeyFormat.
      EcdsaKeyFormat format = EcdsaKeyFormat.newBuilder().build();
      byte[] json = keyManager.keyFormatToJson(format.toByteString());
      fail("Incomplete EcdsaKeyFormat, should have thrown exception");
    } catch (GeneralSecurityException e) {
      // Expected.
    }

    try {  // Wrong serialized key proto.
      KeyData key = KeyData.newBuilder()
          .setTypeUrl("some URL").setValue(ByteString.copyFromUtf8("some value")).build();
      byte[] json = keyManager.keyToJson(key.toByteString());
      fail("Wrong key proto, should have thrown exception");
    } catch (GeneralSecurityException e) {
      // Expected.
      assertExceptionContains(e, "expected serialized EcdsaPrivateKey");
    }

    try {  // Wrong serialized key format proto.
      KeyData format = KeyData.newBuilder()
          .setTypeUrl("some URL").setValue(ByteString.copyFromUtf8("some value")).build();
      byte[] json = keyManager.keyFormatToJson(format.toByteString());
      fail("Wrong key format proto, should have thrown exception");
    } catch (GeneralSecurityException e) {
      // Expected.
      assertExceptionContains(e, "expected serialized EcdsaKeyFormat");
    }
  }
}
