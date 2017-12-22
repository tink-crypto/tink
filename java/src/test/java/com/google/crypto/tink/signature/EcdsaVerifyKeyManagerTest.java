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
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;

import com.google.crypto.tink.PublicKeyVerify;
import com.google.crypto.tink.TestUtil;
import com.google.crypto.tink.Util;
import com.google.crypto.tink.proto.EcdsaKeyFormat;
import com.google.crypto.tink.proto.EcdsaPrivateKey;
import com.google.crypto.tink.proto.EcdsaPublicKey;
import com.google.crypto.tink.proto.EcdsaSignatureEncoding;
import com.google.crypto.tink.proto.EllipticCurveType;
import com.google.crypto.tink.proto.HashType;
import com.google.crypto.tink.proto.KeyData;
import com.google.crypto.tink.subtle.EllipticCurves;
import com.google.crypto.tink.subtle.Random;
import com.google.protobuf.ByteString;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.util.Arrays;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/**
 * Unit tests for EcdsaVerifyKeyManager.
 *
 * <p>TODO(quannguyen): Add more tests.
 */
@RunWith(JUnit4.class)
public class EcdsaVerifyKeyManagerTest {
  private static class HashAndCurveType {
    public HashType hashType;
    public EllipticCurveType curveType;

    public HashAndCurveType(HashType hashType, EllipticCurveType curveType) {
      this.hashType = hashType;
      this.curveType = curveType;
    }
  }

  class RfcTestVector {
    byte[] msg;
    byte[] pubX;
    byte[] pubY;
    byte[] sig;
    HashType hashType;
    EllipticCurveType curveType;

    public RfcTestVector(
        String msg,
        String pubX,
        String pubY,
        String r,
        String s,
        HashType hashType,
        EllipticCurveType curveType) {
      try {
        this.msg = msg.getBytes("UTF-8");
      } catch (Exception ignored) {
        // Ignored
      }
      this.pubX = TestUtil.hexDecode(pubX.toLowerCase());
      this.pubY = TestUtil.hexDecode(pubY.toLowerCase());
      this.sig =
          derEncodeSignature(
              TestUtil.hexDecode(r.toLowerCase()), TestUtil.hexDecode(s.toLowerCase()));
      this.hashType = hashType;
      this.curveType = curveType;
    }
  }

  // Test vectors from https://tools.ietf.org/html/rfc6979#appendix-A.2.
  final RfcTestVector[] rfcTestVectors = {
    new RfcTestVector(
        "sample",
        "60FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB6",
        "7903FE1008B8BC99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C294D4462299",
        "EFD48B2AACB6A8FD1140DD9CD45E81D69D2C877B56AAF991C34D0EA84EAF3716",
        "F7CB1C942D657C41D436C7A1B6E29F65F3E900DBB9AFF4064DC4AB2F843ACDA8",
        HashType.SHA256,
        EllipticCurveType.NIST_P256),
    new RfcTestVector(
        "sample",
        "EC3A4E415B4E19A4568618029F427FA5DA9A8BC4AE92E02E06AAE5286B300C64"
            + "DEF8F0EA9055866064A254515480BC13",
        "8015D9B72D7D57244EA8EF9AC0C621896708A59367F9DFB9F54CA84B3F1C9DB1"
            + "288B231C3AE0D4FE7344FD2533264720",
        "ED0959D5880AB2D869AE7F6C2915C6D60F96507F9CB3E047C0046861DA4A799C"
            + "FE30F35CC900056D7C99CD7882433709",
        "512C8CCEEE3890A84058CE1E22DBC2198F42323CE8ACA9135329F03C068E5112"
            + "DC7CC3EF3446DEFCEB01A45C2667FDD5",
        HashType.SHA512,
        EllipticCurveType.NIST_P384),
    new RfcTestVector(
        "test",
        "01894550D0785932E00EAA23B694F213F8C3121F86DC97A04E5A7167DB4E5BCD3"
            + "71123D46E45DB6B5D5370A7F20FB633155D38FFA16D2BD761DCAC474B9A2F502"
            + "3A4",
        "00493101C962CD4D2FDDF782285E64584139C2F91B47F87FF82354D6630F746A2"
            + "8A0DB25741B5B34A828008B22ACC23F924FAAFBD4D33F81EA66956DFEAA2BFDF"
            + "CF5",
        "013E99020ABF5CEE7525D16B69B229652AB6BDF2AFFCAEF38773B4B7D08725F10"
            + "CDB93482FDCC54EDCEE91ECA4166B2A7C6265EF0CE2BD7051B7CEF945BABD47E"
            + "E6D",
        "01FBD0013C674AA79CB39849527916CE301C66EA7CE8B80682786AD60F98F7E78"
            + "A19CA69EFF5C57400E3B3A0AD66CE0978214D13BAF4E9AC60752F7B155E2DE4D"
            + "CE3",
        HashType.SHA512,
        EllipticCurveType.NIST_P521),
  };

  @Test
  public void testRfcTestVectors() throws Exception {
    for (int i = 0; i < rfcTestVectors.length; i++) {
      RfcTestVector t = rfcTestVectors[i];
      PublicKeyVerify verifier = createVerifier(t);
      try {
        verifier.verify(t.sig, t.msg);
      } catch (GeneralSecurityException e) {
        fail("Valid signature, should not throw exception");
      }
    }
  }

  @Test
  public void testGetPrimitiveWithJCE() throws Exception {
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

      // Sign with JCE's Signature.
      Signature signer = Signature.getInstance(SigUtil.toEcdsaAlgo(hashType));
      signer.initSign(privKey);
      byte[] msg = Random.randBytes(1231);
      signer.update(msg);
      byte[] signature = signer.sign();

      // Create PublicKeyVerify.
      ECPoint w = pubKey.getW();
      PublicKeyVerify verifier =
          createVerifier(
              hashType,
              curveType,
              EcdsaSignatureEncoding.DER,
              w.getAffineX().toByteArray(),
              w.getAffineY().toByteArray());
      try {
        verifier.verify(signature, msg);
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
      ECPrivateKey unusedPrivKey = (ECPrivateKey) keyPair.getPrivate();

      // Create PublicKeyVerify.
      ECPoint w = pubKey.getW();
      try {
        PublicKeyVerify unusedVerifier =
            createVerifier(
                hashType,
                curveType,
                EcdsaSignatureEncoding.DER,
                w.getAffineX().toByteArray(),
                w.getAffineY().toByteArray());
        fail("Unsupported key, should have thrown exception: " + hashType + " " + curveType);
      } catch (GeneralSecurityException expected) {
        // Expected
      }
    }
  }

  @Test
  public void testGetPrimitiveWithUnsupportedEncoding() throws Exception {
    ECParameterSpec ecParams =
        EllipticCurves.getCurveSpec(SigUtil.toCurveType(EllipticCurveType.NIST_P256));
    KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC");
    keyGen.initialize(ecParams);
    KeyPair keyPair = keyGen.generateKeyPair();
    ECPublicKey pubKey = (ECPublicKey) keyPair.getPublic();
    ECPrivateKey unusedPrivKey = (ECPrivateKey) keyPair.getPrivate();

    // Create PublicKeyVerify.
    ECPoint w = pubKey.getW();
    try {
      PublicKeyVerify unusedVerifier =
          createVerifier(
              HashType.SHA256,
              EllipticCurveType.NIST_P256,
              EcdsaSignatureEncoding.IEEE_P1363,
              w.getAffineX().toByteArray(),
              w.getAffineY().toByteArray());
      fail("Unsupported encoding, should have thrown exception.");
    } catch (GeneralSecurityException expected) {
      // Expected
    }
  }

  private PublicKeyVerify createVerifier(RfcTestVector t) throws Exception {
    return createVerifier(t.hashType, t.curveType, EcdsaSignatureEncoding.DER, t.pubX, t.pubY);
  }

  private PublicKeyVerify createVerifier(
      HashType hashType,
      EllipticCurveType curve,
      EcdsaSignatureEncoding encoding,
      byte[] pubX,
      byte[] pubY)
      throws Exception {
    EcdsaPublicKey ecdsaPubKey = TestUtil.createEcdsaPubKey(hashType, curve, encoding, pubX, pubY);
    EcdsaVerifyKeyManager verifyManager = new EcdsaVerifyKeyManager();
    return verifyManager.getPrimitive(ecdsaPubKey);
  }

  private byte[] derEncodeSignature(byte[] r, byte[] s) {
    byte[] derR = derEncodeInteger(r);
    byte[] derS = derEncodeInteger(s);
    byte[] len = derEncodeLength(derR.length + derS.length);

    byte[] sig = new byte[1 + len.length + derR.length + derS.length];
    sig[0] = (byte) 0x30; // DER Sequence tag
    System.arraycopy(len, 0, sig, 1, len.length);
    System.arraycopy(derR, 0, sig, 1 + len.length, derR.length);
    System.arraycopy(derS, 0, sig, 1 + len.length + derR.length, derS.length);
    return sig;
  }

  private byte[] derEncodeInteger(byte[] x) {
    ByteBuffer buf = ByteBuffer.allocate(x.length + 3);
    buf.put((byte) 0x02);
    byte[] derXLen = derEncodeLength(x.length);
    if ((x[0] & 0x80) != 0) {
      derXLen = derEncodeLength(x.length + 1);
      buf.put(derXLen);
      buf.put((byte) 0);
    } else {
      buf.put(derXLen);
    }
    buf.put(x);
    return Arrays.copyOf(buf.array(), buf.position());
  }

  private byte[] derEncodeLength(int length) {
    String res = "";
    if (length >= 128) {
      // Long form
      int lenOfLength = Integer.toHexString(length).length() / 2;
      res += Integer.toHexString(lenOfLength + 128);
    }
    return TestUtil.hexDecode(res + Integer.toHexString(length));
  }

  @Test
  public void testJsonExportAndImport() throws Exception {
    EcdsaVerifyKeyManager keyManager = new EcdsaVerifyKeyManager();
    int keyCount = 3;

    // Prepare example formats and keys.
    ByteString[] formats = new ByteString[keyCount];
    formats[0] = SignatureKeyTemplates.ECDSA_P256.getValue();
    formats[1] = SignatureKeyTemplates.ECDSA_P384.getValue();
    formats[2] = SignatureKeyTemplates.ECDSA_P521.getValue();

    EcdsaPublicKey[] keys = new EcdsaPublicKey[keyCount];
    EcdsaSignKeyManager privateKeyManager = new EcdsaSignKeyManager();
    for (int i = 0; i < keyCount; i++) {
      try {
        keys[i] = ((EcdsaPrivateKey) privateKeyManager.newKey(formats[i])).getPublicKey();
      } catch (Exception e) {
        throw new Exception(e.toString() + "\nFailed for formats[" + i + "]:\n"
            + EcdsaKeyFormat.parseFrom(formats[i]).toString());
      }
    }

    // Check export and import of keys.
    int count = 0;
    for (EcdsaPublicKey key : keys) {
      try {
        byte[] json = keyManager.keyToJson(key.toByteString());
        EcdsaPublicKey keyFromJson = (EcdsaPublicKey) keyManager.jsonToKey(json);
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
    EcdsaVerifyKeyManager keyManager = new EcdsaVerifyKeyManager();

    try {
      byte[] json = "some bad JSON key".getBytes(Util.UTF_8);
      EcdsaPublicKey key = (EcdsaPublicKey) keyManager.jsonToKey(json);
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
      byte[] json = "{\"version\": 0, \"x\": \"some x coordinate\"}".getBytes(Util.UTF_8);
      EcdsaPublicKey key = (EcdsaPublicKey) keyManager.jsonToKey(json);
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
      byte[] json = ("{\"version\": 0, \"params\": {}, "
          + "\"x\": \"x value\", \"y\": \"y value\", \"extraName\": 42}").getBytes(Util.UTF_8);
      EcdsaPublicKey key = (EcdsaPublicKey) keyManager.jsonToKey(json);
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

    try {  // Incomplete params in JSON key.
      byte[] json = ("{\"version\": 0, \"params\": { \"hashType\": \"SHA256\"}, "
          + "\"x\": \"xvalue\", \"y\": \"yvalue\"}").getBytes(Util.UTF_8);
      EcdsaPublicKey key = (EcdsaPublicKey) keyManager.jsonToKey(json);
      fail("Invalid JSON key, should have thrown exception");
    } catch (GeneralSecurityException e) {
      // Expected.
      assertExceptionContains(e, "JSONException");
      assertExceptionContains(e, "Invalid params");
    }

    try {  // An incomplete EcdsaPublicKey.
      EcdsaPublicKey key = EcdsaPublicKey.newBuilder().setVersion(42).build();
      byte[] json = keyManager.keyToJson(key.toByteString());
      fail("Incomplete EcdsaPublicKey, should have thrown exception");
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
      assertExceptionContains(e, "expected serialized EcdsaPublicKey");
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
