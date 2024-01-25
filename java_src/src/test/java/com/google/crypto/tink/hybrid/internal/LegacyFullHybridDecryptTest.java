// Copyright 2024 Google LLC
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

import static com.google.common.truth.Truth.assertThat;
import static org.junit.Assert.assertThrows;

import com.google.crypto.tink.HybridDecrypt;
import com.google.crypto.tink.InsecureSecretKeyAccess;
import com.google.crypto.tink.Registry;
import com.google.crypto.tink.hybrid.internal.testing.LegacyHybridDecryptKeyManager;
import com.google.crypto.tink.hybrid.internal.testing.LegacyHybridEncryptKeyManager;
import com.google.crypto.tink.internal.LegacyProtoKey;
import com.google.crypto.tink.internal.ProtoKeySerialization;
import com.google.crypto.tink.proto.HpkeAead;
import com.google.crypto.tink.proto.HpkeKdf;
import com.google.crypto.tink.proto.HpkeKem;
import com.google.crypto.tink.proto.HpkeParams;
import com.google.crypto.tink.proto.HpkePrivateKey;
import com.google.crypto.tink.proto.HpkePublicKey;
import com.google.crypto.tink.proto.KeyData.KeyMaterialType;
import com.google.crypto.tink.proto.OutputPrefixType;
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
public final class LegacyFullHybridDecryptTest {

  @BeforeClass
  public static void registerKeyManager() throws Exception {
    // We register the legacy key managers as a user would do. Then, we can use the legacy full
    // hybrid encrypts which go to KeyManager registry to get these.
    Registry.registerKeyManager(new LegacyHybridDecryptKeyManager());
    Registry.registerKeyManager(new LegacyHybridEncryptKeyManager());
  }

  private static ByteString getPublicPointAsBytes() throws GeneralSecurityException {
    return ByteString.copyFrom(
        Hex.decode("37fda3567bdbd628e88668c3c8d7e97d1d1253b6d4ea6d44c150f741f1bf4431"));
  }

  private static ByteString getPrivateValue() {
    return ByteString.copyFrom(
        Hex.decode("52c4a758a802cd8b936eceea314432798d5baf2d7e9235dc084ab1b9cfa2f736"));
  }

  // Testvector for HPKE taken from
  // src/main/java/com/google/crypto/tink/hybrid/internal/testing/HpkeTestUtil.java.
  // FIXED_CIPHERTEXT with FIXED_AAD decrypts to FIXED_MESSAGE under the key given by
  // getPrivateP256Value (corresponding to getP256PublicPointAsBytes) when used with
  // DHKEM_P256_HKDF_SHA256, HKDF_SHA256, AES_128_GCM.
  private static final byte[] FIXED_CIPHERTEXT =
      Hex.decode(
          "c202f5f26a59c446531b9e4e880f8730ff0aed444699cb1cd69a2c60e07aba42d77a29b62c7af6b2cfda9c"
              + "1529bb8d23c8");
  private static final byte[] FIXED_AAD = Hex.decode("02");
  private static final byte[] FIXED_MESSAGE = Hex.decode("01");

  private static LegacyProtoKey getFixedProtoPrivateKey(
      OutputPrefixType outputPrefixType, @Nullable Integer idRequirement)
      throws GeneralSecurityException {
    HpkeParams params =
        HpkeParams.newBuilder()
            .setKem(HpkeKem.DHKEM_X25519_HKDF_SHA256)
            .setKdf(HpkeKdf.HKDF_SHA256)
            .setAead(HpkeAead.AES_128_GCM)
            .build();
    HpkePublicKey publicKey =
        HpkePublicKey.newBuilder().setParams(params).setPublicKey(getPublicPointAsBytes()).build();
    HpkePrivateKey privateKey =
        HpkePrivateKey.newBuilder()
            .setPublicKey(publicKey)
            .setPrivateKey(getPrivateValue())
            .build();
    ProtoKeySerialization serialization =
        ProtoKeySerialization.create(
            "type.googleapis.com/custom.HpkePrivateKey",
            privateKey.toByteString(),
            KeyMaterialType.ASYMMETRIC_PRIVATE,
            outputPrefixType,
            idRequirement);
    return new LegacyProtoKey(serialization, InsecureSecretKeyAccess.get());
  }

  @Test
  public void rawTestVectorKey_decrypts() throws Exception {
    LegacyProtoKey protoKey = getFixedProtoPrivateKey(OutputPrefixType.RAW, null);
    HybridDecrypt hybridDecrypt = LegacyFullHybridDecrypt.create(protoKey);

    assertThat(hybridDecrypt.decrypt(FIXED_CIPHERTEXT, FIXED_AAD)).isEqualTo(FIXED_MESSAGE);
  }

  @Test
  public void tinkTestVectorKey_decrypts() throws Exception {
    LegacyProtoKey protoKey = getFixedProtoPrivateKey(OutputPrefixType.TINK, 0x66778899);
    HybridDecrypt hybridDecrypt = LegacyFullHybridDecrypt.create(protoKey);
    byte[] ciphertext = Bytes.concat(Hex.decode("0166778899"), FIXED_CIPHERTEXT);
    assertThat(hybridDecrypt.decrypt(ciphertext, FIXED_AAD)).isEqualTo(FIXED_MESSAGE);
  }

  @Test
  public void crunchyTestVectorKey_decrypts() throws Exception {
    LegacyProtoKey protoKey = getFixedProtoPrivateKey(OutputPrefixType.CRUNCHY, 0x66778899);
    HybridDecrypt hybridDecrypt = LegacyFullHybridDecrypt.create(protoKey);
    byte[] ciphertext = Bytes.concat(Hex.decode("0066778899"), FIXED_CIPHERTEXT);
    assertThat(hybridDecrypt.decrypt(ciphertext, FIXED_AAD)).isEqualTo(FIXED_MESSAGE);
  }

  @Test
  public void legacyTestVectorKey_decrypts() throws Exception {
    LegacyProtoKey protoKey = getFixedProtoPrivateKey(OutputPrefixType.LEGACY, 0x66778899);
    HybridDecrypt hybridDecrypt = LegacyFullHybridDecrypt.create(protoKey);
    byte[] ciphertext = Bytes.concat(Hex.decode("0066778899"), FIXED_CIPHERTEXT);
    assertThat(hybridDecrypt.decrypt(ciphertext, FIXED_AAD)).isEqualTo(FIXED_MESSAGE);
  }

  @Test
  public void rawTestVectorKey_wrongCiphertext_fails() throws Exception {
    LegacyProtoKey protoKey = getFixedProtoPrivateKey(OutputPrefixType.RAW, null);
    HybridDecrypt hybridDecrypt = LegacyFullHybridDecrypt.create(protoKey);
    byte[] ciphertext = Bytes.concat(FIXED_CIPHERTEXT, Hex.decode("00"));
    assertThrows(
        GeneralSecurityException.class, () -> hybridDecrypt.decrypt(ciphertext, FIXED_AAD));
  }

  @Test
  public void tinkTestVectorKey_wrongPrefix_fails() throws Exception {
    LegacyProtoKey protoKey = getFixedProtoPrivateKey(OutputPrefixType.TINK, 0x66778899);
    HybridDecrypt hybridDecrypt = LegacyFullHybridDecrypt.create(protoKey);
    // Note: first byte is expected to be 01.
    byte[] ciphertext = Bytes.concat(Hex.decode("0066778899"), FIXED_CIPHERTEXT);
    assertThrows(
        GeneralSecurityException.class, () -> hybridDecrypt.decrypt(ciphertext, FIXED_AAD));
  }

  @Test
  public void tinkTestVectorKey_wrongPrefix2_fails() throws Exception {
    LegacyProtoKey protoKey = getFixedProtoPrivateKey(OutputPrefixType.TINK, 0x66778899);
    HybridDecrypt hybridDecrypt = LegacyFullHybridDecrypt.create(protoKey);
    // Note: last byte is expected to be 99.
    byte[] ciphertext = Bytes.concat(Hex.decode("0166778898"), FIXED_CIPHERTEXT);
    assertThrows(
        GeneralSecurityException.class, () -> hybridDecrypt.decrypt(ciphertext, FIXED_AAD));
  }
}
