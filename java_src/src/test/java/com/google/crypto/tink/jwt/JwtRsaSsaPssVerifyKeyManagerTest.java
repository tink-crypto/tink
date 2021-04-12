// Copyright 2020 Google LLC
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
package com.google.crypto.tink.jwt;

import static com.google.common.truth.Truth.assertThat;
import static org.junit.Assert.assertThrows;

import com.google.crypto.tink.KeyTypeManager;
import com.google.crypto.tink.proto.JwtRsaSsaPssAlgorithm;
import com.google.crypto.tink.proto.JwtRsaSsaPssKeyFormat;
import com.google.crypto.tink.proto.JwtRsaSsaPssPrivateKey;
import com.google.crypto.tink.proto.JwtRsaSsaPssPublicKey;
import com.google.crypto.tink.proto.KeyData.KeyMaterialType;
import com.google.crypto.tink.testing.TestUtil;
import com.google.protobuf.ByteString;
import java.security.GeneralSecurityException;
import java.security.spec.RSAKeyGenParameterSpec;
import junitparams.JUnitParamsRunner;
import junitparams.Parameters;
import org.junit.Test;
import org.junit.runner.RunWith;

/** Unit tests for RsaSsaPssVerifyKeyManager. */
@RunWith(JUnitParamsRunner.class)
public final class JwtRsaSsaPssVerifyKeyManagerTest {
  private final JwtRsaSsaPssSignKeyManager signManager = new JwtRsaSsaPssSignKeyManager();
  private final KeyTypeManager.KeyFactory<JwtRsaSsaPssKeyFormat, JwtRsaSsaPssPrivateKey> factory =
      signManager.keyFactory();
  private final JwtRsaSsaPssVerifyKeyManager verifyManager = new JwtRsaSsaPssVerifyKeyManager();

  private static Object[] parametersAlgoAndSize() {
    return new Object[] {
      new Object[] {JwtRsaSsaPssAlgorithm.PS256, 2048},
      new Object[] {JwtRsaSsaPssAlgorithm.PS256, 3072},
      new Object[] {JwtRsaSsaPssAlgorithm.PS256, 4096},
      new Object[] {JwtRsaSsaPssAlgorithm.PS384, 2048},
      new Object[] {JwtRsaSsaPssAlgorithm.PS384, 3072},
      new Object[] {JwtRsaSsaPssAlgorithm.PS384, 4096},
      new Object[] {JwtRsaSsaPssAlgorithm.PS512, 2048},
      new Object[] {JwtRsaSsaPssAlgorithm.PS512, 3072},
      new Object[] {JwtRsaSsaPssAlgorithm.PS512, 4096},
    };
  }

  @Test
  public void basics() throws Exception {
    assertThat(verifyManager.getKeyType())
        .isEqualTo("type.googleapis.com/google.crypto.tink.JwtRsaSsaPssPublicKey");
    assertThat(verifyManager.getVersion()).isEqualTo(0);
    assertThat(verifyManager.keyMaterialType()).isEqualTo(KeyMaterialType.ASYMMETRIC_PUBLIC);
  }

  @Test
  public void validateKey_empty_throw() throws Exception {
    assertThrows(
        GeneralSecurityException.class,
        () -> verifyManager.validateKey(JwtRsaSsaPssPublicKey.getDefaultInstance()));
  }

  @Test
  @Parameters(method = "parametersAlgoAndSize")
  public void validateKey_ok(JwtRsaSsaPssAlgorithm algorithm, int keySize) throws Exception {
    if (TestUtil.isTsan()) {
      // factory.createKey is too slow in Tsan.
      return;
    }
    JwtRsaSsaPssKeyFormat keyFormat =
        JwtRsaSsaPssKeyFormat.newBuilder()
            .setAlgorithm(algorithm)
            .setModulusSizeInBits(keySize)
            .setPublicExponent(ByteString.copyFrom(RSAKeyGenParameterSpec.F4.toByteArray()))
            .build();
    JwtRsaSsaPssPrivateKey privateKey = factory.createKey(keyFormat);
    JwtRsaSsaPssPublicKey publicKey = signManager.getPublicKey(privateKey);
    verifyManager.validateKey(publicKey);
  }

  @Test
  @Parameters(method = "parametersAlgoAndSize")
  public void createPrimitive_ok(JwtRsaSsaPssAlgorithm algorithm, int keySize) throws Exception {
    if (TestUtil.isTsan()) {
      // factory.createKey is too slow in Tsan.
      return;
    }
    JwtRsaSsaPssKeyFormat keyFormat =
        JwtRsaSsaPssKeyFormat.newBuilder()
            .setAlgorithm(algorithm)
            .setModulusSizeInBits(keySize)
            .setPublicExponent(ByteString.copyFrom(RSAKeyGenParameterSpec.F4.toByteArray()))
            .build();
    JwtRsaSsaPssPrivateKey privateKey = factory.createKey(keyFormat);
    JwtRsaSsaPssPublicKey publicKey = signManager.getPublicKey(privateKey);
    JwtPublicKeySign signer = signManager.getPrimitive(privateKey, JwtPublicKeySign.class);
    JwtPublicKeyVerify verifier = verifyManager.getPrimitive(publicKey, JwtPublicKeyVerify.class);
    RawJwt token = new RawJwt.Builder().build();
    JwtValidator validator = new JwtValidator.Builder().build();
    verifier.verifyAndDecode(signer.signAndEncode(token), validator);
  }

  @Test
  @Parameters(method = "parametersAlgoAndSize")
  public void createPrimitive_anotherKey_throw(JwtRsaSsaPssAlgorithm algorithm, int keySize)
      throws Exception {
    if (TestUtil.isTsan()) {
      // factory.createKey is too slow in Tsan.
      return;
    }
    JwtRsaSsaPssKeyFormat keyFormat =
        JwtRsaSsaPssKeyFormat.newBuilder()
            .setAlgorithm(algorithm)
            .setModulusSizeInBits(keySize)
            .setPublicExponent(ByteString.copyFrom(RSAKeyGenParameterSpec.F4.toByteArray()))
            .build();
    JwtRsaSsaPssPrivateKey privateKey = factory.createKey(keyFormat);
    // Create a different key.
    JwtRsaSsaPssPublicKey publicKey = signManager.getPublicKey(factory.createKey(keyFormat));
    JwtPublicKeySign signer = signManager.getPrimitive(privateKey, JwtPublicKeySign.class);
    JwtPublicKeyVerify verifier = verifyManager.getPrimitive(publicKey, JwtPublicKeyVerify.class);
    RawJwt token = new RawJwt.Builder().build();
    JwtValidator validator = new JwtValidator.Builder().build();
    assertThrows(
        GeneralSecurityException.class,
        () -> verifier.verifyAndDecode(signer.signAndEncode(token), validator));
  }
}
