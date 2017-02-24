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

import static junit.framework.Assert.assertTrue;

import com.google.cloud.crypto.tink.CommonProto.EllipticCurveType;
import com.google.cloud.crypto.tink.CommonProto.HashType;
import com.google.cloud.crypto.tink.EcdsaProto.EcdsaKeyFormat;
import com.google.cloud.crypto.tink.EcdsaProto.EcdsaParams;
import com.google.cloud.crypto.tink.EcdsaProto.EcdsaPrivateKey;
import com.google.cloud.crypto.tink.EcdsaProto.EcdsaPublicKey;
import com.google.cloud.crypto.tink.PublicKeySign;
import com.google.cloud.crypto.tink.PublicKeyVerify;
import com.google.cloud.crypto.tink.TinkProto.KeyFormat;
import com.google.protobuf.Any;
import com.google.protobuf.ByteString;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import org.junit.Test;

/**
 * Unit tests for EcdsaSignKeyManager.
 * TODO(quannguyen): Add more tests.
 */
public class EcdsaSignKeyManagerTest {
  @Test
  public void testBasic() throws Exception {
    EcdsaSignKeyManager signManager = new EcdsaSignKeyManager();
    EcdsaParams ecdsaParams = EcdsaParams.newBuilder()
        .setHashType(HashType.SHA256)
        .setCurve(EllipticCurveType.NIST_P256)
        .build();
    EcdsaKeyFormat ecdsaFormat = EcdsaKeyFormat.newBuilder()
        .setParams(ecdsaParams)
        .build();
    KeyFormat keyFormat = KeyFormat.newBuilder().setFormat(Any.pack(ecdsaFormat)).build();
    Any privKey = signManager.newKey(keyFormat);
    PublicKeySign signer = signManager.getPrimitive(privKey);
    String data = "hello";
    byte[] signature = signer.sign(data.getBytes("UTF-8"));
    EcdsaVerifyKeyManager verifyManager = new EcdsaVerifyKeyManager();
    PublicKeyVerify verifier = verifyManager.getPrimitive(
        Any.pack(privKey.unpack(EcdsaPrivateKey.class).getPublicKey()));
    assertTrue(verifier.verify(signature, data.getBytes("UTF-8")));
  }
}
