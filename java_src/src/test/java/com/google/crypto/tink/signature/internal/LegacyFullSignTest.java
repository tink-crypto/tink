// Copyright 2024 Google LLC
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

package com.google.crypto.tink.signature.internal;

import static com.google.common.truth.Truth.assertThat;

import com.google.crypto.tink.InsecureSecretKeyAccess;
import com.google.crypto.tink.PublicKeySign;
import com.google.crypto.tink.PublicKeyVerify;
import com.google.crypto.tink.Registry;
import com.google.crypto.tink.internal.LegacyProtoKey;
import com.google.crypto.tink.internal.ProtoKeySerialization;
import com.google.crypto.tink.proto.Ed25519PrivateKey;
import com.google.crypto.tink.proto.Ed25519PublicKey;
import com.google.crypto.tink.proto.KeyData.KeyMaterialType;
import com.google.crypto.tink.proto.OutputPrefixType;
import com.google.crypto.tink.signature.internal.testing.LegacyPublicKeySignKeyManager;
import com.google.crypto.tink.signature.internal.testing.LegacyPublicKeyVerifyKeyManager;
import com.google.crypto.tink.subtle.Ed25519Verify;
import com.google.crypto.tink.subtle.Hex;
import com.google.crypto.tink.util.Bytes;
import com.google.protobuf.ByteString;
import java.security.GeneralSecurityException;
import java.util.Arrays;
import javax.annotation.Nullable;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

@RunWith(JUnit4.class)
public final class LegacyFullSignTest {
  @BeforeClass
  public static void registerKeyManager() throws Exception {
    // We register the legacy key managers as a user would do. Then, we can use the legacy full
    // sign objects which go to KeyManager registry to get these.
    Registry.registerKeyManager(new LegacyPublicKeySignKeyManager());
    Registry.registerKeyManager(new LegacyPublicKeyVerifyKeyManager());
  }

  private static ByteString getPublicValue() throws GeneralSecurityException {
    // Point is taken from /testing/Ed25519TestUtil.java
    return ByteString.copyFrom(
        Hex.decode("ea42941a6dc801484390b2955bc7376d172eeb72640a54e5b50c95efa2fc6ad8"));
  }

  private static ByteString getPrivateValue() {
    // Point is taken from /testing/Ed25519TestUtil.java
    return ByteString.copyFrom(
        Hex.decode("9cac7d19aeecc563a3dff7bcae0fbbbc28087b986c49a3463077dd5281437e81"));
  }

  private static LegacyProtoKey getFixedProtoPrivateKey(
      OutputPrefixType outputPrefixType, @Nullable Integer idRequirement)
      throws GeneralSecurityException {
    Ed25519PublicKey publicKey =
        Ed25519PublicKey.newBuilder().setKeyValue(getPublicValue()).build();
    Ed25519PrivateKey privateKey =
        Ed25519PrivateKey.newBuilder()
            .setPublicKey(publicKey)
            .setKeyValue(getPrivateValue())
            .build();
    ProtoKeySerialization serialization =
        ProtoKeySerialization.create(
            "type.googleapis.com/custom.Ed25519PrivateKey",
            privateKey.toByteString(),
            KeyMaterialType.ASYMMETRIC_PRIVATE,
            outputPrefixType,
            idRequirement);
    return new LegacyProtoKey(serialization, InsecureSecretKeyAccess.get());
  }

  private static com.google.crypto.tink.signature.Ed25519PublicKey publicKeyNoPrefix()
      throws GeneralSecurityException {
    return com.google.crypto.tink.signature.Ed25519PublicKey.create(
        Bytes.copyFrom(getPublicValue().toByteArray()));
  }

  private static final byte[] FIXED_MESSAGE = Hex.decode("01");

  @Test
  public void rawKey_verifyWorksCorrectly() throws Exception {
    LegacyProtoKey protoKey = getFixedProtoPrivateKey(OutputPrefixType.RAW, null);
    PublicKeySign publicKeySign = LegacyFullSign.create(protoKey);
    PublicKeyVerify publicKeyVerify = Ed25519Verify.create(publicKeyNoPrefix());
    publicKeyVerify.verify(publicKeySign.sign(FIXED_MESSAGE), FIXED_MESSAGE);
  }

  @Test
  public void tinkKey_verifyWorksCorrectly() throws Exception {
    LegacyProtoKey protoKey = getFixedProtoPrivateKey(OutputPrefixType.TINK, 0x22662288);
    PublicKeySign publicKeySign = LegacyFullSign.create(protoKey);

    byte[] signature = publicKeySign.sign(FIXED_MESSAGE);
    assertThat(Arrays.copyOf(signature, 5)).isEqualTo(Hex.decode("0122662288"));
    byte[] signatureNoPrefix = Arrays.copyOfRange(signature, 5, signature.length);
    PublicKeyVerify publicKeyVerify = Ed25519Verify.create(publicKeyNoPrefix());
    publicKeyVerify.verify(signatureNoPrefix, FIXED_MESSAGE);
  }

  @Test
  public void crunchyKey_verifyWorksCorrectly() throws Exception {
    LegacyProtoKey protoKey = getFixedProtoPrivateKey(OutputPrefixType.CRUNCHY, 0x22662288);
    PublicKeySign publicKeySign = LegacyFullSign.create(protoKey);

    byte[] signature = publicKeySign.sign(FIXED_MESSAGE);
    assertThat(Arrays.copyOf(signature, 5)).isEqualTo(Hex.decode("0022662288"));
    byte[] signatureNoPrefix = Arrays.copyOfRange(signature, 5, signature.length);
    PublicKeyVerify publicKeyVerify = Ed25519Verify.create(publicKeyNoPrefix());
    publicKeyVerify.verify(signatureNoPrefix, FIXED_MESSAGE);
  }

  @Test
  public void legacyKey_verifyWorksCorrectly() throws Exception {
    LegacyProtoKey protoKey = getFixedProtoPrivateKey(OutputPrefixType.LEGACY, 0x22662288);
    PublicKeySign publicKeySign = LegacyFullSign.create(protoKey);

    byte[] signature = publicKeySign.sign(FIXED_MESSAGE);
    assertThat(Arrays.copyOf(signature, 5)).isEqualTo(Hex.decode("0022662288"));
    byte[] signatureNoPrefix = Arrays.copyOfRange(signature, 5, signature.length);
    PublicKeyVerify publicKeyVerify = Ed25519Verify.create(publicKeyNoPrefix());
    publicKeyVerify.verify(
        signatureNoPrefix,
        com.google.crypto.tink.subtle.Bytes.concat(FIXED_MESSAGE, Hex.decode("00")));
  }
}
