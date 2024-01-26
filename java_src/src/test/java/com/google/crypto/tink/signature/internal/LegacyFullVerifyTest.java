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

import static org.junit.Assert.assertThrows;

import com.google.crypto.tink.InsecureSecretKeyAccess;
import com.google.crypto.tink.PublicKeyVerify;
import com.google.crypto.tink.Registry;
import com.google.crypto.tink.internal.LegacyProtoKey;
import com.google.crypto.tink.internal.ProtoKeySerialization;
import com.google.crypto.tink.proto.Ed25519PublicKey;
import com.google.crypto.tink.proto.KeyData.KeyMaterialType;
import com.google.crypto.tink.proto.OutputPrefixType;
import com.google.crypto.tink.signature.internal.testing.LegacyPublicKeySignKeyManager;
import com.google.crypto.tink.signature.internal.testing.LegacyPublicKeyVerifyKeyManager;
import com.google.crypto.tink.subtle.Bytes;
import com.google.crypto.tink.subtle.Hex;
import com.google.protobuf.ByteString;
import java.security.GeneralSecurityException;
import javax.annotation.Nullable;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

@RunWith(JUnit4.class)
public final class LegacyFullVerifyTest {
  @BeforeClass
  public static void registerKeyManager() throws Exception {
    // We register the legacy key managers as a user would do. Then, we can use the legacy full
    // verify objects which go to KeyManager registry to get these.
    Registry.registerKeyManager(new LegacyPublicKeySignKeyManager());
    Registry.registerKeyManager(new LegacyPublicKeyVerifyKeyManager());
  }

  private static ByteString getPublicValue() throws GeneralSecurityException {
    return ByteString.copyFrom(
        Hex.decode("ea42941a6dc801484390b2955bc7376d172eeb72640a54e5b50c95efa2fc6ad8"));
  }

  private static LegacyProtoKey getFixedProtoPublicKey(
      OutputPrefixType outputPrefixType, @Nullable Integer idRequirement)
      throws GeneralSecurityException {
    Ed25519PublicKey publicKey =
        Ed25519PublicKey.newBuilder().setKeyValue(getPublicValue()).build();
    ProtoKeySerialization serialization =
        ProtoKeySerialization.create(
            "type.googleapis.com/custom.Ed25519PublicKey",
            publicKey.toByteString(),
            KeyMaterialType.ASYMMETRIC_PRIVATE,
            outputPrefixType,
            idRequirement);
    return new LegacyProtoKey(serialization, InsecureSecretKeyAccess.get());
  }

  // Testvector for HPKE taken from
  // src/main/java/com/google/crypto/tink/signature/internal/testing/Ed25519TestUtil.java
  // FIXED_SIGNATURE is a valid signature for FIXED_MESSAGE under the key given by
  // getPrivateValue (corresponding to getPublicValue) when used with
  // DHKEM_P256_HKDF_SHA256, HKDF_SHA256, AES_128_GCM.
  private static final byte[] FIXED_SIGNATURE =
      Hex.decode(
          "3431985050f48157551262d591d0f1f25b9c6808fce4345066cb8216d48fcd9feafa4b24949a7f8c"
              + "abdc16a51030a19d7514c9685c221475bf3cfc363472ee0a");
  private static final byte[] FIXED_MESSAGE = Hex.decode("aa");

  @Test
  public void testVectorKey_raw_verifyWorks() throws Exception {
    LegacyProtoKey protoKey = getFixedProtoPublicKey(OutputPrefixType.RAW, null);
    PublicKeyVerify publicKeyVerify = LegacyFullVerify.create(protoKey);

    publicKeyVerify.verify(FIXED_SIGNATURE, FIXED_MESSAGE);
  }

  @Test
  public void testVectorKey_raw_wrongSignature_throws() throws Exception {
    LegacyProtoKey protoKey = getFixedProtoPublicKey(OutputPrefixType.RAW, null);
    PublicKeyVerify publicKeyVerify = LegacyFullVerify.create(protoKey);

    assertThrows(
        GeneralSecurityException.class,
        () ->
            publicKeyVerify.verify(Bytes.concat(FIXED_SIGNATURE, Hex.decode("00")), FIXED_MESSAGE));
  }

  @Test
  public void testVectorKey_tink_verifyWorks() throws Exception {
    LegacyProtoKey protoKey = getFixedProtoPublicKey(OutputPrefixType.TINK, 0x55885577);
    PublicKeyVerify publicKeyVerify = LegacyFullVerify.create(protoKey);

    publicKeyVerify.verify(Bytes.concat(Hex.decode("0155885577"), FIXED_SIGNATURE), FIXED_MESSAGE);
  }

  @Test
  public void testVectorKey_tink_wrongOutputPrefix_throws() throws Exception {
    LegacyProtoKey protoKey = getFixedProtoPublicKey(OutputPrefixType.TINK, 0x55885577);
    PublicKeyVerify publicKeyVerify = LegacyFullVerify.create(protoKey);

    assertThrows(
        GeneralSecurityException.class,
        () ->
            publicKeyVerify.verify(
                Bytes.concat(Hex.decode("0055885577"), FIXED_SIGNATURE), FIXED_MESSAGE));
  }

  @Test
  public void testVectorKey_crunchy_verifyWorks() throws Exception {
    LegacyProtoKey protoKey = getFixedProtoPublicKey(OutputPrefixType.CRUNCHY, 0x55885577);
    PublicKeyVerify publicKeyVerify = LegacyFullVerify.create(protoKey);

    publicKeyVerify.verify(Bytes.concat(Hex.decode("0055885577"), FIXED_SIGNATURE), FIXED_MESSAGE);
  }

  @Test
  public void testVectorKey_crunchy_wrongOutputPrefix_fails() throws Exception {
    LegacyProtoKey protoKey = getFixedProtoPublicKey(OutputPrefixType.CRUNCHY, 0x55885576);
    PublicKeyVerify publicKeyVerify = LegacyFullVerify.create(protoKey);

    assertThrows(
        GeneralSecurityException.class,
        () ->
            publicKeyVerify.verify(
                Bytes.concat(Hex.decode("0055885577"), FIXED_SIGNATURE), FIXED_MESSAGE));
  }

  @Test
  public void testVectorKey_legacy_verifyWorks() throws Exception {
    LegacyProtoKey protoKey = getFixedProtoPublicKey(OutputPrefixType.LEGACY, 0x55885577);
    PublicKeyVerify publicKeyVerify = LegacyFullVerify.create(protoKey);

    publicKeyVerify.verify(
        Hex.decode(
            "0055885577"
                + "e828586415b1226c118617a2b56b923b6717e83c4d265fcb4e2cdf3cb902ce7b9b1ecd840"
                + "5cb4e6a8e248ef5478891b5b6f80f737df16594f88662595d8f140e"),
        FIXED_MESSAGE);
  }

  @Test
  public void testVector_legacy_wrongOutputPrefix_fails() throws Exception {
    LegacyProtoKey protoKey = getFixedProtoPublicKey(OutputPrefixType.TINK, 0x55885576);
    PublicKeyVerify publicKeyVerify = LegacyFullVerify.create(protoKey);

    assertThrows(
        GeneralSecurityException.class,
        () ->
            publicKeyVerify.verify(
                Hex.decode(
                    "0055885577"
                        + "e828586415b1226c118617a2b56b923b6717e83c4d265fcb4e2cdf3cb902ce7b9b1ecd8"
                        + "405cb4e6a8e248ef5478891b5b6f80f737df16594f88662595d8f140e"),
                FIXED_MESSAGE));
  }
}
