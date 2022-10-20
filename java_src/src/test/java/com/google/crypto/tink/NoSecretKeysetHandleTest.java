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

package com.google.crypto.tink;

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.junit.Assert.assertThrows;

import com.google.common.truth.Expect;
import com.google.crypto.tink.config.TinkConfig;
import com.google.crypto.tink.proto.KeyStatusType;
import com.google.crypto.tink.proto.Keyset;
import com.google.crypto.tink.proto.OutputPrefixType;
import com.google.crypto.tink.testing.TestUtil;
import java.io.IOException;
import java.security.GeneralSecurityException;
import org.junit.BeforeClass;
import org.junit.Rule;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Tests for NoSecretKeysetHandle. */
@RunWith(JUnit4.class)
public class NoSecretKeysetHandleTest {
  @Rule public final Expect expect = Expect.create();

  @BeforeClass
  public static void setUp() throws GeneralSecurityException {
    TinkConfig.register();
  }

  @SuppressWarnings("deprecation")  // This is a test for deprecated functions
  @Test
  public void withTypeAsymmetricPublic_deprecated_noSecretKeysetHandle_sameAs_readNoSecret()
      throws Exception {
    KeysetHandle privateHandle = KeysetHandle.generateNew(KeyTemplates.get("ECDSA_P256"));
    Keyset keyset = privateHandle.getPublicKeysetHandle().getKeyset();

    Keyset keyset2 = NoSecretKeysetHandle.parseFrom(keyset.toByteArray()).getKeyset();
    Keyset keyset3 =
        NoSecretKeysetHandle.read(BinaryKeysetReader.withBytes(keyset.toByteArray())).getKeyset();

    Keyset keyset4 = KeysetHandle.readNoSecret(keyset.toByteArray()).getKeyset();
    Keyset keyset5 =
        KeysetHandle.readNoSecret(BinaryKeysetReader.withBytes(keyset.toByteArray())).getKeyset();

    expect.that(keyset).isEqualTo(keyset2);
    expect.that(keyset).isEqualTo(keyset3);
    expect.that(keyset).isEqualTo(keyset4);
    expect.that(keyset).isEqualTo(keyset5);
  }

  @SuppressWarnings("deprecation")  // This is a test for the deprecated functions
  @Test
  public void withTypeSymmetric_deprecated_noSecretKeysetHandle_sameAs_readNoSecret()
      throws Exception {
    String keyValue = "01234567890123456";
    Keyset keyset =
        TestUtil.createKeyset(
            TestUtil.createKey(
                TestUtil.createHmacKeyData(keyValue.getBytes(UTF_8), 16),
                42,
                KeyStatusType.ENABLED,
                OutputPrefixType.TINK));

    assertThrows(
        GeneralSecurityException.class, () -> NoSecretKeysetHandle.parseFrom(keyset.toByteArray()));
    assertThrows(
        GeneralSecurityException.class,
        () -> NoSecretKeysetHandle.read(BinaryKeysetReader.withBytes(keyset.toByteArray())));

    assertThrows(
        GeneralSecurityException.class, () -> KeysetHandle.readNoSecret(keyset.toByteArray()));
    assertThrows(
        GeneralSecurityException.class,
        () -> KeysetHandle.readNoSecret(BinaryKeysetReader.withBytes(keyset.toByteArray())));
  }

  @SuppressWarnings("deprecation")  // This is a test for deprecated functions
  @Test
  public void withTypeAsymmetricPrivate_deprecated_noSecretKeysetHandle_sameAs_readNoSecret()
      throws Exception {
    Keyset keyset = KeysetHandle.generateNew(KeyTemplates.get("ECDSA_P256")).getKeyset();

    assertThrows(
        GeneralSecurityException.class, () -> NoSecretKeysetHandle.parseFrom(keyset.toByteArray()));
    assertThrows(
        GeneralSecurityException.class,
        () -> NoSecretKeysetHandle.read(BinaryKeysetReader.withBytes(keyset.toByteArray())));
    assertThrows(
        GeneralSecurityException.class,
        () -> NoSecretKeysetHandle.read(BinaryKeysetReader.withBytes(keyset.toByteArray())));

    assertThrows(
        GeneralSecurityException.class, () -> KeysetHandle.readNoSecret(keyset.toByteArray()));
    assertThrows(
        GeneralSecurityException.class,
        () -> KeysetHandle.readNoSecret(BinaryKeysetReader.withBytes(keyset.toByteArray())));
  }

  @SuppressWarnings("deprecation")  // This is a test for deprecated functions
  @Test
  public void withEmptyKeyset_deprecated_noSecretKeysetHandle_sameAs_readNoSecret()
      throws Exception {
    assertThrows(GeneralSecurityException.class, () -> NoSecretKeysetHandle.parseFrom(new byte[0]));
    assertThrows(
        GeneralSecurityException.class,
        () -> NoSecretKeysetHandle.read(BinaryKeysetReader.withBytes(new byte[0])));

    assertThrows(GeneralSecurityException.class, () -> KeysetHandle.readNoSecret(new byte[0]));
    assertThrows(
        GeneralSecurityException.class,
        () -> KeysetHandle.readNoSecret(BinaryKeysetReader.withBytes(new byte[0])));
  }

  @SuppressWarnings("deprecation")  // This is a test for the deprecated function
  @Test
  public void withInvalidKeyset_deprecated_noSecretKeysetHandle_almostSameAs_readNoSecret()
      throws Exception {
    byte[] invalidSerializedProto = new byte[] {0x00, 0x01, 0x02};
    assertThrows(
        GeneralSecurityException.class,
        () -> NoSecretKeysetHandle.parseFrom(invalidSerializedProto));
    assertThrows(
        IOException.class, // This is inconsistent
        () -> NoSecretKeysetHandle.read(BinaryKeysetReader.withBytes(invalidSerializedProto)));

    assertThrows(
        GeneralSecurityException.class, () -> KeysetHandle.readNoSecret(invalidSerializedProto));
    assertThrows(
        GeneralSecurityException.class,
        () -> KeysetHandle.readNoSecret(BinaryKeysetReader.withBytes(invalidSerializedProto)));
  }
}
