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

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertTrue;

import com.google.cloud.crypto.tink.CommonProto.EllipticCurveType;
import com.google.cloud.crypto.tink.CommonProto.HashType;
import com.google.cloud.crypto.tink.CryptoFormat;
import com.google.cloud.crypto.tink.EcdsaProto.EcdsaPrivateKey;
import com.google.cloud.crypto.tink.KeysetHandle;
import com.google.cloud.crypto.tink.PublicKeySign;
import com.google.cloud.crypto.tink.PublicKeyVerify;
import com.google.cloud.crypto.tink.TestUtil;
import com.google.cloud.crypto.tink.TinkProto.KeyStatusType;
import com.google.cloud.crypto.tink.TinkProto.Keyset.Key;
import com.google.cloud.crypto.tink.TinkProto.OutputPrefixType;
import java.util.Arrays;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Unit tests for {@link PublicKeyVerifyFactory}. */
@RunWith(JUnit4.class)
//TODO(quannguyen): Add more tests.
public class PublicKeyVerifyFactoryTest {

  @Before
  public void setUp() throws Exception {
    PublicKeyVerifyFactory.registerStandardKeyTypes();
    PublicKeySignFactory.registerStandardKeyTypes();
  }

  @Test
  public void testSignVerify() throws Exception {
    EcdsaPrivateKey privKey1 = TestUtil.generateEcdsaPrivKey(
        EllipticCurveType.NIST_P521, HashType.SHA512);
    Key primary = TestUtil.createKey(
        privKey1,
        1,
        KeyStatusType.ENABLED,
        OutputPrefixType.TINK);
    KeysetHandle keysetHandle = TestUtil.createKeysetHandle(
        TestUtil.createKeyset(primary));
    PublicKeySign signer = PublicKeySignFactory.getPrimitive(keysetHandle);
    byte[] plaintext = "plaintext".getBytes("UTF-8");
    byte[] sig = signer.sign(plaintext);
    byte[] prefix = Arrays.copyOfRange(sig, 0, CryptoFormat.NON_RAW_PREFIX_SIZE);
    assertArrayEquals(prefix, CryptoFormat.getOutputPrefix(primary));
    // Create PublicKeyVerifyFactory
    KeysetHandle keysetHandle1 = TestUtil.createKeysetHandle(
        TestUtil.createKeyset(TestUtil.createKey(privKey1.getPublicKey(), 1, KeyStatusType.ENABLED,
        OutputPrefixType.TINK)));
    PublicKeyVerify verifier = PublicKeyVerifyFactory.getPrimitive(keysetHandle1);
    assertTrue(verifier.verify(sig, plaintext));
  }
}
