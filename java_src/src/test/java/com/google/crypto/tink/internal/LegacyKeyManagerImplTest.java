// Copyright 2023 Google LLC
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

package com.google.crypto.tink.internal;

import static com.google.common.truth.Truth.assertThat;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;

import com.google.crypto.tink.Mac;
import com.google.crypto.tink.mac.internal.HmacProtoSerialization;
import com.google.crypto.tink.proto.HashType;
import com.google.crypto.tink.proto.HmacKey;
import com.google.crypto.tink.proto.HmacKeyFormat;
import com.google.crypto.tink.proto.HmacParams;
import com.google.crypto.tink.proto.KeyData;
import com.google.crypto.tink.proto.KeyData.KeyMaterialType;
import com.google.crypto.tink.subtle.Hex;
import com.google.crypto.tink.subtle.PrfMac;
import com.google.crypto.tink.util.SecretBytes;
import com.google.protobuf.ByteString;
import com.google.protobuf.ExtensionRegistryLite;
import java.security.GeneralSecurityException;
import javax.annotation.Nullable;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

@RunWith(JUnit4.class)
public final class LegacyKeyManagerImplTest {

  private static LegacyKeyManagerImpl<Mac> keyManager;

  private static com.google.crypto.tink.mac.HmacKey createHmacKey(
      com.google.crypto.tink.mac.HmacParameters parameters, @Nullable Integer idRequirement)
      throws GeneralSecurityException {
    return com.google.crypto.tink.mac.HmacKey.builder()
        .setParameters(parameters)
        .setKeyBytes(SecretBytes.randomBytes(parameters.getKeySizeBytes()))
        .setIdRequirement(idRequirement)
        .build();
  }

  @BeforeClass
  public static void register() throws GeneralSecurityException {
    HmacProtoSerialization.register();
    MutablePrimitiveRegistry.globalInstance()
        .registerPrimitiveConstructor(
            PrimitiveConstructor.create(
                PrfMac::create, com.google.crypto.tink.mac.HmacKey.class, Mac.class));
    MutableKeyCreationRegistry.globalInstance()
        .add(
            LegacyKeyManagerImplTest::createHmacKey,
            com.google.crypto.tink.mac.HmacParameters.class);

    keyManager =
        LegacyKeyManagerImpl.create(
            "type.googleapis.com/google.crypto.tink.HmacKey",
            Mac.class,
            KeyMaterialType.SYMMETRIC,
            HmacKey.parser());
  }

  @Test
  public void getPrimitive_messageLite_works() throws Exception {
    HmacKey key =
        HmacKey.newBuilder()
            .setVersion(0)
            .setParams(HmacParams.newBuilder().setHash(HashType.SHA1).setTagSize(16))
            .setKeyValue(
                ByteString.copyFrom(
                    Hex.decode("816aa4c3ee066310ac1e6666cf830c375355c3c8ba18cfe1f50a48c988b46272")))
            .build();

    Mac mac = keyManager.getPrimitive(key);
    byte[] message =
        Hex.decode(
            "220248f5e6d7a49335b3f91374f18bb8b0ff5e8b9a5853f3cfb293855d78301d837a0a2eb9e4f056f06c08361"
                + "bd07180ee802651e69726c28910d2baef379606815dcbab01d0dc7acb0ba8e65a2928130da0522f2b2b3d05260"
                + "885cf1c64f14ca3145313c685b0274bf6a1cb38e4f99895c6a8cc72fbe0e52c01766fede78a1a");
    byte[] tag = Hex.decode("17cb2e9e98b748b5ae0f7078ea5519e5");

    mac.verifyMac(tag, message);
  }

  @Test
  public void getPrimitive_byteString_works() throws Exception {
    HmacKey key =
        HmacKey.newBuilder()
            .setVersion(0)
            .setParams(HmacParams.newBuilder().setHash(HashType.SHA1).setTagSize(16))
            .setKeyValue(
                ByteString.copyFrom(
                    Hex.decode("816aa4c3ee066310ac1e6666cf830c375355c3c8ba18cfe1f50a48c988b46272")))
            .build();

    Mac mac = keyManager.getPrimitive(key.toByteString());
    byte[] message =
        Hex.decode(
            "220248f5e6d7a49335b3f91374f18bb8b0ff5e8b9a5853f3cfb293855d78301d837a0a2eb9e4f056f06c08361"
                + "bd07180ee802651e69726c28910d2baef379606815dcbab01d0dc7acb0ba8e65a2928130da0522f2b2b3d05260"
                + "885cf1c64f14ca3145313c685b0274bf6a1cb38e4f99895c6a8cc72fbe0e52c01766fede78a1a");
    byte[] tag = Hex.decode("17cb2e9e98b748b5ae0f7078ea5519e5");

    mac.verifyMac(tag, message);
  }

  @Test
  public void getPrimitive_invalidKey_throws() throws Exception {
    HmacKey key =
        HmacKey.newBuilder()
            .setVersion(0)
            .setParams(HmacParams.newBuilder().setHash(HashType.UNKNOWN_HASH).setTagSize(16))
            .build();

    assertThrows(GeneralSecurityException.class, () -> keyManager.getPrimitive(key));
  }

  @Test
  public void newKey_byteString_works() throws Exception {
    HmacKeyFormat keyFormat =
        HmacKeyFormat.newBuilder()
            .setKeySize(32)
            .setParams(HmacParams.newBuilder().setHash(HashType.SHA1).setTagSize(16))
            .build();

    HmacKey key1 = (HmacKey) keyManager.newKey(keyFormat.toByteString());
    HmacKey key2 = (HmacKey) keyManager.newKey(keyFormat.toByteString());
    assertThat(key1.getKeyValue().size()).isEqualTo(32);
    assertThat(key1.getKeyValue()).isNotEqualTo(key2.getKeyValue());
    assertThat(key1.getParams()).isEqualTo(keyFormat.getParams());
  }

  @Test
  public void newKey_messageLite_works() throws Exception {
    HmacKeyFormat keyFormat =
        HmacKeyFormat.newBuilder()
            .setKeySize(32)
            .setParams(HmacParams.newBuilder().setHash(HashType.SHA1).setTagSize(16))
            .build();

    HmacKey key1 = (HmacKey) keyManager.newKey(keyFormat);
    HmacKey key2 = (HmacKey) keyManager.newKey(keyFormat);
    assertThat(key1.getKeyValue().size()).isEqualTo(32);
    assertThat(key1.getKeyValue()).isNotEqualTo(key2.getKeyValue());
    assertThat(key1.getParams()).isEqualTo(keyFormat.getParams());
  }

  @Test
  public void newKeyData_works() throws Exception {
    HmacKeyFormat keyFormat =
        HmacKeyFormat.newBuilder()
            .setKeySize(32)
            .setParams(HmacParams.newBuilder().setHash(HashType.SHA1).setTagSize(16))
            .build();

    KeyData keyData1 = keyManager.newKeyData(keyFormat.toByteString());
    KeyData keyData2 = keyManager.newKeyData(keyFormat.toByteString());
    assertThat(keyData1.getKeyMaterialType()).isEqualTo(KeyMaterialType.SYMMETRIC);
    assertThat(keyData1.getTypeUrl()).isEqualTo("type.googleapis.com/google.crypto.tink.HmacKey");
    HmacKey key1 = HmacKey.parseFrom(keyData1.getValue(), ExtensionRegistryLite.getEmptyRegistry());
    HmacKey key2 = HmacKey.parseFrom(keyData2.getValue(), ExtensionRegistryLite.getEmptyRegistry());
    assertThat(key1.getParams()).isEqualTo(keyFormat.getParams());
    assertThat(key1.getKeyValue().size()).isEqualTo(32);
    assertThat(key1.getKeyValue()).isNotEqualTo(key2.getKeyValue());
  }

  @Test
  public void doesSupport_works() throws Exception {
    assertTrue(keyManager.doesSupport("type.googleapis.com/google.crypto.tink.HmacKey"));
    assertFalse(keyManager.doesSupport("type.googleapis.com/google.crypto.tink.SomeOtherKey"));
  }

  @Test
  public void getKeyType_works() throws Exception {
    assertThat(keyManager.getKeyType()).isEqualTo("type.googleapis.com/google.crypto.tink.HmacKey");
  }

  @Test
  public void getVersion_works() throws Exception {
    assertThat(keyManager.getVersion()).isEqualTo(0);
  }

  @Test
  public void getPrimitiveClass_works() throws Exception {
    assertThat(keyManager.getPrimitiveClass()).isEqualTo(Mac.class);
  }
}
