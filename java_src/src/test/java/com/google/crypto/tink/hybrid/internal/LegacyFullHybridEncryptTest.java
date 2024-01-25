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

import com.google.crypto.tink.HybridDecrypt;
import com.google.crypto.tink.HybridEncrypt;
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
import com.google.crypto.tink.subtle.Hex;
import com.google.protobuf.ByteString;
import java.security.GeneralSecurityException;
import javax.annotation.Nullable;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

@RunWith(JUnit4.class)
public final class LegacyFullHybridEncryptTest {

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

  private static LegacyProtoKey getFixedProtoPublicKey(
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
    ProtoKeySerialization serialization =
        ProtoKeySerialization.create(
            "type.googleapis.com/custom.HpkePublicKey",
            publicKey.toByteString(),
            KeyMaterialType.ASYMMETRIC_PRIVATE,
            outputPrefixType,
            idRequirement);
    return new LegacyProtoKey(serialization, InsecureSecretKeyAccess.get());
  }

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

  private static final byte[] FIXED_AAD = Hex.decode("abcdef");
  private static final byte[] FIXED_MESSAGE = Hex.decode("07");

  @Test
  public void rawTestVectorKey_decrypts() throws Exception {
    HybridEncrypt hybridEncrypt =
        LegacyFullHybridEncrypt.create(getFixedProtoPublicKey(OutputPrefixType.RAW, null));
    HybridDecrypt hybridDecrypt =
        LegacyFullHybridDecrypt.create(getFixedProtoPrivateKey(OutputPrefixType.RAW, null));

    assertThat(hybridDecrypt.decrypt(hybridEncrypt.encrypt(FIXED_MESSAGE, FIXED_AAD), FIXED_AAD))
        .isEqualTo(FIXED_MESSAGE);
  }

  @Test
  public void tinkTestVectorKey_decrypts() throws Exception {
    HybridEncrypt hybridEncrypt =
        LegacyFullHybridEncrypt.create(getFixedProtoPublicKey(OutputPrefixType.TINK, 0x22334455));
    HybridDecrypt hybridDecrypt =
        LegacyFullHybridDecrypt.create(getFixedProtoPrivateKey(OutputPrefixType.TINK, 0x22334455));

    assertThat(hybridDecrypt.decrypt(hybridEncrypt.encrypt(FIXED_MESSAGE, FIXED_AAD), FIXED_AAD))
        .isEqualTo(FIXED_MESSAGE);
  }

  @Test
  public void crunchyTestVectorKey_decrypts() throws Exception {
    HybridEncrypt hybridEncrypt =
        LegacyFullHybridEncrypt.create(
            getFixedProtoPublicKey(OutputPrefixType.CRUNCHY, 0x22334455));
    HybridDecrypt hybridDecrypt =
        LegacyFullHybridDecrypt.create(
            getFixedProtoPrivateKey(OutputPrefixType.CRUNCHY, 0x22334455));

    assertThat(hybridDecrypt.decrypt(hybridEncrypt.encrypt(FIXED_MESSAGE, FIXED_AAD), FIXED_AAD))
        .isEqualTo(FIXED_MESSAGE);
  }

  @Test
  public void legacyTestVectorKey_decrypts() throws Exception {
    HybridEncrypt hybridEncrypt =
        LegacyFullHybridEncrypt.create(getFixedProtoPublicKey(OutputPrefixType.LEGACY, 0x66778899));
    HybridDecrypt hybridDecrypt =
        LegacyFullHybridDecrypt.create(
            getFixedProtoPrivateKey(OutputPrefixType.LEGACY, 0x66778899));

    assertThat(hybridDecrypt.decrypt(hybridEncrypt.encrypt(FIXED_MESSAGE, FIXED_AAD), FIXED_AAD))
        .isEqualTo(FIXED_MESSAGE);
  }
}
