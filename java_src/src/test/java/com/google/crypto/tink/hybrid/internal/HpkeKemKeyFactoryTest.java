// Copyright 2022 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
///////////////////////////////////////////////////////////////////////////////

package com.google.crypto.tink.hybrid.internal;

import static org.junit.Assert.assertThrows;

import com.google.common.truth.Expect;
import com.google.crypto.tink.proto.HpkeKem;
import com.google.crypto.tink.proto.HpkeParams;
import com.google.crypto.tink.proto.HpkePrivateKey;
import com.google.crypto.tink.proto.HpkePublicKey;
import com.google.crypto.tink.subtle.X25519;
import com.google.crypto.tink.util.Bytes;
import com.google.protobuf.ByteString;
import java.security.GeneralSecurityException;
import org.junit.BeforeClass;
import org.junit.Rule;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Unit tests for {@link HpkeKemKeyFactoryTest}. */
@RunWith(JUnit4.class)
public final class HpkeKemKeyFactoryTest {
  private static byte[] privateKeyBytes;
  private static byte[] publicKeyBytes;

  @Rule public final Expect expect = Expect.create();

  @BeforeClass
  public static void generateKeyMaterial() throws GeneralSecurityException {
    privateKeyBytes = X25519.generatePrivateKey();
    publicKeyBytes = X25519.publicFromPrivate(privateKeyBytes);
  }

  @Test
  public void createKemPrivateKey_fromValidHpkePrivateKey_succeeds()
      throws GeneralSecurityException {
    HpkePrivateKey hpkePrivateKey =
        HpkePrivateKey.newBuilder()
            .setPrivateKey(ByteString.copyFrom(privateKeyBytes))
            .setPublicKey(
                HpkePublicKey.newBuilder()
                    .setParams(
                        HpkeParams.newBuilder().setKem(HpkeKem.DHKEM_X25519_HKDF_SHA256).build()))
            .build();
    HpkeKemPrivateKey hpkeKemPrivateKey = HpkeKemKeyFactory.createPrivate(hpkePrivateKey);
    expect
        .that(hpkeKemPrivateKey.getSerializedPrivate())
        .isEqualTo(Bytes.copyFrom(privateKeyBytes));
    expect.that(hpkeKemPrivateKey.getSerializedPublic()).isEqualTo(Bytes.copyFrom(publicKeyBytes));
  }

  @Test
  public void createKemPrivateKey_fromInvalidHpkeKemParams_fails() throws GeneralSecurityException {
    HpkePrivateKey hpkePrivateKey =
        HpkePrivateKey.newBuilder()
            .setPrivateKey(ByteString.copyFrom(privateKeyBytes))
            .setPublicKey(
                HpkePublicKey.newBuilder()
                    .setParams(HpkeParams.newBuilder().setKem(HpkeKem.KEM_UNKNOWN).build())
                    .build())
            .build();
    assertThrows(
        GeneralSecurityException.class, () -> HpkeKemKeyFactory.createPrivate(hpkePrivateKey));
  }
}
