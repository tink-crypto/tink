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

import com.google.cloud.crypto.tink.CommonProto.EllipticCurveType;
import com.google.cloud.crypto.tink.CommonProto.HashType;
import com.google.cloud.crypto.tink.EcdsaProto.EcdsaKeyFormat;
import com.google.cloud.crypto.tink.EcdsaProto.EcdsaParams;
import com.google.cloud.crypto.tink.EcdsaProto.EcdsaPrivateKey;
import com.google.cloud.crypto.tink.EcdsaProto.EcdsaPublicKey;
import com.google.cloud.crypto.tink.PublicKeySign;
import com.google.cloud.crypto.tink.PublicKeyVerify;
import com.google.cloud.crypto.tink.TestUtil;
import com.google.cloud.crypto.tink.TinkProto.KeyFormat;
import com.google.cloud.crypto.tink.subtle.Random;
import com.google.protobuf.Any;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/**
 * Unit tests for EcdsaSignKeyManager.
 * TODO(quannguyen): Add more tests.
 */
@RunWith(JUnit4.class)
public class EcdsaSignKeyManagerTest {
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
    HashAndCurveType[] hashAndCurves = {
      new HashAndCurveType(HashType.SHA256, EllipticCurveType.NIST_P256),
      new HashAndCurveType(HashType.SHA512, EllipticCurveType.NIST_P384),
      new HashAndCurveType(HashType.SHA512, EllipticCurveType.NIST_P521)};
    for (int i = 0; i < hashAndCurves.length; i++) {
      HashType hashType = hashAndCurves[i].hashType;
      EllipticCurveType curveType = hashAndCurves[i].curveType;
      EcdsaSignKeyManager signManager = new EcdsaSignKeyManager();
      EcdsaParams ecdsaParams = EcdsaParams.newBuilder()
          .setHashType(hashType)
          .setCurve(curveType)
          .build();
      EcdsaKeyFormat ecdsaFormat = EcdsaKeyFormat.newBuilder()
          .setParams(ecdsaParams)
          .build();
      KeyFormat keyFormat = KeyFormat.newBuilder().setFormat(Any.pack(ecdsaFormat)).build();
      Any privKey = signManager.newKey(keyFormat);
      PublicKeySign signer = signManager.getPrimitive(privKey);
      byte[] signature = signer.sign(msg);
      EcdsaVerifyKeyManager verifyManager = new EcdsaVerifyKeyManager();
      PublicKeyVerify verifier = verifyManager.getPrimitive(
          Any.pack(privKey.unpack(EcdsaPrivateKey.class).getPublicKey()));
      try {
        verifier.verify(signature, msg);
      } catch (GeneralSecurityException e) {
        fail("Valid signature, should not throw exception");
      }

      // Creates another signer and checks that the signature can not be verified with a different
      // verifier.
      Any privKey1 = signManager.newKey(keyFormat);
      PublicKeySign signer1 = signManager.getPrimitive(privKey1);
      byte[] signature1 = signer1.sign(msg);
      try {
        verifier.verify(signature1, msg);
        fail("Invalid signature, should have thrown exception");
      } catch (GeneralSecurityException expected) {
        // Expected
      }
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
      EcdsaParams ecdsaParams = EcdsaParams.newBuilder()
          .setHashType(hashType)
          .setCurve(curveType)
          .build();
      EcdsaKeyFormat ecdsaFormat = EcdsaKeyFormat.newBuilder()
          .setParams(ecdsaParams)
          .build();
      KeyFormat keyFormat = KeyFormat.newBuilder().setFormat(Any.pack(ecdsaFormat)).build();
      try {
        Any unusedPrivKey = signManager.newKey(keyFormat);
        fail("Unsupported key format, should have thrown exception: " + hashType + " "
            + curveType);
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
      new HashAndCurveType(HashType.SHA512, EllipticCurveType.NIST_P521)};
    for (int i = 0; i < hashAndCurves.length; i++) {
      HashType hashType = hashAndCurves[i].hashType;
      EllipticCurveType curveType = hashAndCurves[i].curveType;
      ECParameterSpec ecParams = SigUtil.getCurveSpec(curveType);
      KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC");
      keyGen.initialize(ecParams);
      KeyPair keyPair = keyGen.generateKeyPair();
      ECPublicKey pubKey = (ECPublicKey) keyPair.getPublic();
      ECPrivateKey privKey = (ECPrivateKey) keyPair.getPrivate();

      ECPoint w = pubKey.getW();
      EcdsaPublicKey ecdsaPubKey = TestUtil.createEcdsaPubKey(hashType, curveType,
          w.getAffineX().toByteArray(), w.getAffineY().toByteArray());
      EcdsaPrivateKey ecdsaPrivKey = TestUtil.createEcdsaPrivKey(ecdsaPubKey,
          privKey.getS().toByteArray());
      EcdsaSignKeyManager signManager = new EcdsaSignKeyManager();
      PublicKeySign signer = signManager.getPrimitive(
          Any.pack(ecdsaPrivKey));
      PublicKeyVerify verifier = (new EcdsaVerifyKeyManager()).getPrimitive(Any.pack(ecdsaPubKey));
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
      ECParameterSpec ecParams = SigUtil.getCurveSpec(curveType);
      KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC");
      keyGen.initialize(ecParams);
      KeyPair keyPair = keyGen.generateKeyPair();
      ECPublicKey pubKey = (ECPublicKey) keyPair.getPublic();
      ECPrivateKey privKey = (ECPrivateKey) keyPair.getPrivate();

      ECPoint w = pubKey.getW();
      EcdsaPublicKey ecdsaPubKey = TestUtil.createEcdsaPubKey(hashType, curveType,
          w.getAffineX().toByteArray(), w.getAffineY().toByteArray());
      EcdsaPrivateKey ecdsaPrivKey = TestUtil.createEcdsaPrivKey(ecdsaPubKey,
          privKey.getS().toByteArray());

      EcdsaSignKeyManager signManager = new EcdsaSignKeyManager();
      try {
        PublicKeySign unusedSigner = signManager.getPrimitive(
            Any.pack(ecdsaPrivKey));
        fail("Unsupported key, should have thrown exception: " + hashType + " "
            + curveType);
      } catch (GeneralSecurityException expected) {
        // Expected
      }
    }
  }

}
