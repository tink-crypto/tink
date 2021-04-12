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

package com.google.crypto.tink.prf;

import static com.google.common.truth.Truth.assertThat;
import static com.google.crypto.tink.testing.KeyTypeManagerTestUtil.testKeyTemplateCompatible;
import static java.nio.charset.StandardCharsets.UTF_8;
import static org.junit.Assert.assertThrows;

import com.google.crypto.tink.KeyTemplate;
import com.google.crypto.tink.KeyTypeManager;
import com.google.crypto.tink.proto.HashType;
import com.google.crypto.tink.proto.HkdfPrfKey;
import com.google.crypto.tink.proto.HkdfPrfKeyFormat;
import com.google.crypto.tink.proto.HkdfPrfParams;
import com.google.crypto.tink.proto.KeyData.KeyMaterialType;
import com.google.crypto.tink.subtle.Enums;
import com.google.crypto.tink.subtle.Random;
import com.google.crypto.tink.subtle.prf.HkdfStreamingPrf;
import com.google.crypto.tink.subtle.prf.StreamingPrf;
import com.google.protobuf.ByteString;
import com.google.protobuf.ExtensionRegistryLite;
import java.io.InputStream;
import java.security.GeneralSecurityException;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Tests for HkdfPrfKeyManager. */
@RunWith(JUnit4.class)
public class HkdfPrfKeyManagerTest {
  private final HkdfPrfKeyManager manager = new HkdfPrfKeyManager();
  private final KeyTypeManager.KeyFactory<HkdfPrfKeyFormat, HkdfPrfKey> factory =
      manager.keyFactory();

  @Test
  public void basics() throws Exception {
    assertThat(manager.getKeyType()).isEqualTo("type.googleapis.com/google.crypto.tink.HkdfPrfKey");
    assertThat(manager.getVersion()).isEqualTo(0);
    assertThat(manager.keyMaterialType()).isEqualTo(KeyMaterialType.SYMMETRIC);
  }

  @Test
  public void validateKey_empty_throws() throws Exception {
    HkdfPrfKey key = HkdfPrfKey.getDefaultInstance();
    assertThrows(GeneralSecurityException.class, () -> manager.validateKey(key));
  }

  @Test
  public void validateKey_valid32ByteKey_works() throws Exception {
    manager.validateKey(
        HkdfPrfKey.newBuilder()
            .setVersion(0)
            .setKeyValue(ByteString.copyFrom(Random.randBytes(32)))
            .setParams(HkdfPrfParams.newBuilder().setHash(HashType.SHA256))
            .build());
  }

  @Test
  public void validateKey_invalid31ByteKey_throws() throws Exception {
    HkdfPrfKey key =
        HkdfPrfKey.newBuilder()
            .setVersion(0)
            .setKeyValue(ByteString.copyFrom(Random.randBytes(31)))
            .setParams(HkdfPrfParams.newBuilder().setHash(HashType.SHA256))
            .build();
    assertThrows(GeneralSecurityException.class, () -> manager.validateKey(key));
  }

  @Test
  public void validateKey_validSha512Key_works() throws Exception {
    manager.validateKey(
        HkdfPrfKey.newBuilder()
            .setVersion(0)
            .setKeyValue(ByteString.copyFrom(Random.randBytes(32)))
            .setParams(HkdfPrfParams.newBuilder().setHash(HashType.SHA512))
            .build());
  }

  @Test
  public void validateKey_valid33ByteKey_works() throws Exception {
    manager.validateKey(
        HkdfPrfKey.newBuilder()
            .setVersion(0)
            .setKeyValue(ByteString.copyFrom(Random.randBytes(33)))
            .setParams(HkdfPrfParams.newBuilder().setHash(HashType.SHA256))
            .build());
  }

  @Test
  public void validateKey_validKeyWithSalt_works() throws Exception {
    manager.validateKey(
        HkdfPrfKey.newBuilder()
            .setVersion(0)
            .setKeyValue(ByteString.copyFrom(Random.randBytes(32)))
            .setParams(
                HkdfPrfParams.newBuilder()
                    .setSalt(ByteString.copyFrom(Random.randBytes(5)))
                    .setHash(HashType.SHA256))
            .build());
  }

  @Test
  public void validateKey_invalidSha1Key_throws() throws Exception {
    HkdfPrfKey key =
        HkdfPrfKey.newBuilder()
            .setVersion(0)
            .setKeyValue(ByteString.copyFrom(Random.randBytes(32)))
            .setParams(HkdfPrfParams.newBuilder().setHash(HashType.SHA1))
            .build();
    assertThrows(GeneralSecurityException.class, () -> manager.validateKey(key));
  }

  @Test
  public void validateKey_invalidKeyVersion_throws() throws Exception {
    HkdfPrfKey key =
        HkdfPrfKey.newBuilder()
            .setVersion(1)
            .setKeyValue(ByteString.copyFrom(Random.randBytes(32)))
            .setParams(HkdfPrfParams.newBuilder().setHash(HashType.SHA256))
            .build();
    assertThrows(GeneralSecurityException.class, () -> manager.validateKey(key));
  }

  @Test
  public void validateKeyFormat_empty_throws() throws Exception {
    HkdfPrfKeyFormat keyFormat = HkdfPrfKeyFormat.getDefaultInstance();
    assertThrows(GeneralSecurityException.class, () -> factory.validateKeyFormat(keyFormat));
  }

  @Test
  public void validateKeyFormat_valid32Byte() throws Exception {
    factory.validateKeyFormat(
        HkdfPrfKeyFormat.newBuilder()
            .setKeySize(32)
            .setParams(HkdfPrfParams.newBuilder().setHash(HashType.SHA256))
            .build());
  }

  @Test
  public void validateKeyFormat_invalid31Byte_throws() throws Exception {
    HkdfPrfKeyFormat keyFormat =
        HkdfPrfKeyFormat.newBuilder()
            .setKeySize(31)
            .setParams(HkdfPrfParams.newBuilder().setHash(HashType.SHA256))
            .build();
    assertThrows(GeneralSecurityException.class, () -> factory.validateKeyFormat(keyFormat));
  }

  @Test
  public void validateKeyFormat_validSha512() throws Exception {
    factory.validateKeyFormat(
        HkdfPrfKeyFormat.newBuilder()
            .setKeySize(32)
            .setParams(HkdfPrfParams.newBuilder().setHash(HashType.SHA512))
            .build());
  }

  @Test
  public void validateKeyFormat_valid33Bytes() throws Exception {
    factory.validateKeyFormat(
        HkdfPrfKeyFormat.newBuilder()
            .setKeySize(33)
            .setParams(HkdfPrfParams.newBuilder().setHash(HashType.SHA256))
            .build());
  }

  @Test
  public void validateKeyFormat_validWithSalt() throws Exception {
    factory.validateKeyFormat(
        HkdfPrfKeyFormat.newBuilder()
            .setKeySize(32)
            .setParams(
                HkdfPrfParams.newBuilder()
                    .setSalt(ByteString.copyFrom(Random.randBytes(5)))
                    .setHash(HashType.SHA256))
            .build());
  }

  @Test
  public void validateKeyFormat_invalidSha1_throws() throws Exception {
    HkdfPrfKeyFormat format =
        HkdfPrfKeyFormat.newBuilder()
            .setKeySize(32)
            .setParams(HkdfPrfParams.newBuilder().setHash(HashType.SHA1))
            .build();
    assertThrows(GeneralSecurityException.class, () -> factory.validateKeyFormat(format));
  }

  @Test
  public void createKey_valuesAreOk() throws Exception {
    HkdfPrfKeyFormat format =
        HkdfPrfKeyFormat.newBuilder()
            .setKeySize(77)
            .setParams(
                HkdfPrfParams.newBuilder()
                    .setSalt(ByteString.copyFrom(Random.randBytes(5)))
                    .setHash(HashType.SHA256))
            .build();
    HkdfPrfKey key = factory.createKey(format);
    assertThat(key.getVersion()).isEqualTo(0);
    assertThat(key.getKeyValue()).hasSize(77);
    assertThat(key.getParams()).isEqualTo(format.getParams());
  }

  @Test
  public void createPrimitive_works() throws Exception {
    HkdfPrfKey key =
        HkdfPrfKey.newBuilder()
            .setKeyValue(ByteString.copyFromUtf8("super secret key value"))
            .setParams(
                HkdfPrfParams.newBuilder()
                    .setSalt(ByteString.copyFromUtf8("some salt"))
                    .setHash(HashType.SHA256))
            .build();
    StreamingPrf managerPrf = manager.getPrimitive(key, StreamingPrf.class);
    InputStream managerInput = managerPrf.computePrf("my input".getBytes(UTF_8));
    byte[] managerOutput = new byte[10];
    assertThat(managerInput.read(managerOutput)).isEqualTo(10);

    HkdfStreamingPrf directPrf =
        new HkdfStreamingPrf(
            Enums.HashType.SHA256,
            "super secret key value".getBytes(UTF_8),
            "some salt".getBytes(UTF_8));
    InputStream directInput = directPrf.computePrf("my input".getBytes(UTF_8));

    byte[] directOutput = new byte[10];
    assertThat(directInput.read(directOutput)).isEqualTo(10);

    assertThat(directOutput).isEqualTo(managerOutput);
  }

  /** Smoke test getPrimitive for PrfSet via the HkdfPrfKeymanager. */
  @Test
  public void createPrfSetPrimitive_works() throws Exception {
    HkdfPrfKey key =
        HkdfPrfKey.newBuilder()
            .setKeyValue(ByteString.copyFromUtf8("super secret key value"))
            .setParams(
                HkdfPrfParams.newBuilder()
                    .setSalt(ByteString.copyFromUtf8("some salt"))
                    .setHash(HashType.SHA256))
            .build();
    manager.getPrimitive(key, Prf.class);
  }

  @Test
  public void testHkdfSha256Template() throws Exception {
    KeyTemplate kt = HkdfPrfKeyManager.hkdfSha256Template();
    assertThat(kt.getTypeUrl()).isEqualTo(new HkdfPrfKeyManager().getKeyType());
    assertThat(kt.getOutputPrefixType()).isEqualTo(KeyTemplate.OutputPrefixType.RAW);

    HkdfPrfKeyFormat format =
        HkdfPrfKeyFormat.parseFrom(kt.getValue(), ExtensionRegistryLite.getEmptyRegistry());
    assertThat(format.getKeySize()).isEqualTo(32);
    assertThat(format.getParams().getHash()).isEqualTo(HashType.SHA256);
  }

  @Test
  public void testKeyTemplateAndManagerCompatibility() throws Exception {
    HkdfPrfKeyManager manager = new HkdfPrfKeyManager();

    testKeyTemplateCompatible(manager, HkdfPrfKeyManager.hkdfSha256Template());
  }
}
