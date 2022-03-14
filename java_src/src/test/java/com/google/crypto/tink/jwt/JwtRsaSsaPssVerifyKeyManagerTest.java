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
import org.junit.Test;
import org.junit.experimental.theories.DataPoints;
import org.junit.experimental.theories.FromDataPoints;
import org.junit.experimental.theories.Theories;
import org.junit.experimental.theories.Theory;
import org.junit.runner.RunWith;

/** Unit tests for RsaSsaPssVerifyKeyManager. */
@RunWith(Theories.class)
public final class JwtRsaSsaPssVerifyKeyManagerTest {
  private final JwtRsaSsaPssSignKeyManager signManager = new JwtRsaSsaPssSignKeyManager();
  private final KeyTypeManager.KeyFactory<JwtRsaSsaPssKeyFormat, JwtRsaSsaPssPrivateKey> factory =
      signManager.keyFactory();
  private final JwtRsaSsaPssVerifyKeyManager verifyManager = new JwtRsaSsaPssVerifyKeyManager();

  @DataPoints("algorithmParam")
  public static final JwtRsaSsaPssAlgorithm[] ALGO_PARAMETER =
      new JwtRsaSsaPssAlgorithm[] {
        JwtRsaSsaPssAlgorithm.PS256, JwtRsaSsaPssAlgorithm.PS384, JwtRsaSsaPssAlgorithm.PS512
      };

  @DataPoints("size")
  public static final int[] SIZE = new int[] {2048, 3072, 4096};

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

  // Note: we use Theory as a parametrized test -- different from what the Theory framework intends.
  @Theory
  public void validateKey_ok(
      @FromDataPoints("algorithmParam") JwtRsaSsaPssAlgorithm algorithm,
      @FromDataPoints("size") int keySize)
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
    JwtRsaSsaPssPublicKey publicKey = signManager.getPublicKey(privateKey);
    verifyManager.validateKey(publicKey);
  }
}
