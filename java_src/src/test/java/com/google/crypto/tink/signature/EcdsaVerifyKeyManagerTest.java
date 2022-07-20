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

import static com.google.common.truth.Truth.assertThat;
import static org.junit.Assert.assertThrows;

import com.google.crypto.tink.PublicKeyVerify;
import com.google.crypto.tink.internal.KeyTypeManager;
import com.google.crypto.tink.proto.EcdsaKeyFormat;
import com.google.crypto.tink.proto.EcdsaParams;
import com.google.crypto.tink.proto.EcdsaPrivateKey;
import com.google.crypto.tink.proto.EcdsaPublicKey;
import com.google.crypto.tink.proto.EcdsaSignatureEncoding;
import com.google.crypto.tink.proto.EllipticCurveType;
import com.google.crypto.tink.proto.HashType;
import com.google.crypto.tink.proto.KeyData.KeyMaterialType;
import com.google.crypto.tink.signature.internal.SigUtil;
import com.google.crypto.tink.subtle.EllipticCurves;
import com.google.crypto.tink.subtle.Hex;
import com.google.crypto.tink.subtle.Random;
import com.google.crypto.tink.subtle.SubtleUtil;
import com.google.crypto.tink.testing.TestUtil;
import com.google.crypto.tink.testing.TestUtil.BytesMutation;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
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
  private final EcdsaSignKeyManager signManager = new EcdsaSignKeyManager();
  private final EcdsaVerifyKeyManager verifyManager = new EcdsaVerifyKeyManager();
  private final KeyTypeManager.KeyFactory<EcdsaKeyFormat, EcdsaPrivateKey> factory =
      signManager.keyFactory();

  private EcdsaPrivateKey createKey(
      HashType hashType, EllipticCurveType curveType, EcdsaSignatureEncoding encoding)
      throws GeneralSecurityException {
    return factory.createKey(
        EcdsaKeyFormat.newBuilder()
            .setParams(
                EcdsaParams.newBuilder()
                    .setHashType(hashType)
                    .setCurve(curveType)
                    .setEncoding(encoding))
            .build());
  }

  @Test
  public void basics() throws Exception {
    assertThat(verifyManager.getKeyType())
        .isEqualTo("type.googleapis.com/google.crypto.tink.EcdsaPublicKey");
    assertThat(verifyManager.getVersion()).isEqualTo(0);
    assertThat(verifyManager.keyMaterialType()).isEqualTo(KeyMaterialType.ASYMMETRIC_PUBLIC);
  }

  @Test
  public void validateKey_usualPublicKey() throws Exception {
    verifyManager.validateKey(
        signManager.getPublicKey(
            createKey(HashType.SHA256, EllipticCurveType.NIST_P256, EcdsaSignatureEncoding.DER)));
    verifyManager.validateKey(
        signManager.getPublicKey(
            createKey(
                HashType.SHA256, EllipticCurveType.NIST_P256, EcdsaSignatureEncoding.IEEE_P1363)));
    verifyManager.validateKey(
        signManager.getPublicKey(
            createKey(HashType.SHA384, EllipticCurveType.NIST_P384, EcdsaSignatureEncoding.DER)));
    verifyManager.validateKey(
        signManager.getPublicKey(
            createKey(
                HashType.SHA384, EllipticCurveType.NIST_P384, EcdsaSignatureEncoding.IEEE_P1363)));
    verifyManager.validateKey(
        signManager.getPublicKey(
            createKey(HashType.SHA512, EllipticCurveType.NIST_P384, EcdsaSignatureEncoding.DER)));
    verifyManager.validateKey(
        signManager.getPublicKey(
            createKey(
                HashType.SHA512, EllipticCurveType.NIST_P384, EcdsaSignatureEncoding.IEEE_P1363)));
    verifyManager.validateKey(
        signManager.getPublicKey(
            createKey(HashType.SHA512, EllipticCurveType.NIST_P521, EcdsaSignatureEncoding.DER)));
    verifyManager.validateKey(
        signManager.getPublicKey(
            createKey(
                HashType.SHA512, EllipticCurveType.NIST_P521, EcdsaSignatureEncoding.IEEE_P1363)));
  }

  private EcdsaPublicKey validPublicKey() throws Exception {
    return signManager.getPublicKey(
        createKey(HashType.SHA256, EllipticCurveType.NIST_P256, EcdsaSignatureEncoding.DER));
  }

  @Test
  public void validateKey_wrongVersion_throws() throws Exception {
    EcdsaPublicKey wrongVersionKey =
        EcdsaPublicKey.newBuilder(validPublicKey()).setVersion(1).build();
    assertThrows(GeneralSecurityException.class, () -> verifyManager.validateKey(wrongVersionKey));
  }

  @Test
  public void validateKey_badParams_throws() throws Exception {
    EcdsaPublicKey validKey = validPublicKey();
    EcdsaPublicKey wrongHashKey =
        EcdsaPublicKey.newBuilder(validKey)
            .setParams(
                EcdsaParams.newBuilder(validKey.getParams())
                    .setHashType(HashType.SHA256)
                    .setCurve(EllipticCurveType.NIST_P521)
                    .build())
            .build();
    assertThrows(GeneralSecurityException.class, () -> verifyManager.validateKey(wrongHashKey));
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
      this.sig = TestUtil.hexDecode((r + s).toLowerCase());
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
      verifier.verify(t.sig, t.msg);
      for (BytesMutation mutation : TestUtil.generateMutations(t.sig)) {
        assertThrows(
            String.format(
                "Invalid signature, should have thrown exception : sig = %s, msg = %s,"
                    + " description = %s",
                Hex.encode(mutation.value), Hex.encode(t.msg), mutation.description),
            GeneralSecurityException.class,
            () -> verifier.verify(mutation.value, t.msg));
      }
    }
  }

  private static class HashAndCurveType {
    public HashType hashType;
    public EllipticCurveType curveType;

    public HashAndCurveType(HashType hashType, EllipticCurveType curveType) {
      this.hashType = hashType;
      this.curveType = curveType;
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
      Signature signer =
          Signature.getInstance(SubtleUtil.toEcdsaAlgo(SigUtil.toHashType(hashType)));
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
      verifier.verify(signature, msg);
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
      assertThrows(
          "Unsupported key, should have thrown exception: " + hashType + " " + curveType,
          GeneralSecurityException.class,
          () -> {
            PublicKeyVerify unusedVerifier =
                createVerifier(
                    hashType,
                    curveType,
                    EcdsaSignatureEncoding.DER,
                    w.getAffineX().toByteArray(),
                    w.getAffineY().toByteArray());
          });
    }
  }

  private PublicKeyVerify createVerifier(RfcTestVector t) throws Exception {
    return createVerifier(
        t.hashType, t.curveType, EcdsaSignatureEncoding.IEEE_P1363, t.pubX, t.pubY);
  }

  private PublicKeyVerify createVerifier(
      HashType hashType,
      EllipticCurveType curve,
      EcdsaSignatureEncoding encoding,
      byte[] pubX,
      byte[] pubY)
      throws Exception {
    EcdsaPublicKey ecdsaPubKey = TestUtil.createEcdsaPubKey(hashType, curve, encoding, pubX, pubY);
    // Validating so that we throw exceptions when it is expected.
    verifyManager.validateKey(ecdsaPubKey);
    return verifyManager.getPrimitive(ecdsaPubKey, PublicKeyVerify.class);
  }
}
