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

package com.google.crypto.tink.mac;

import static com.google.common.truth.Truth.assertThat;
import static com.google.crypto.tink.testing.KeyTypeManagerTestUtil.testKeyTemplateCompatible;
import static org.junit.Assert.assertThrows;

import com.google.crypto.tink.KeyTemplate;
import com.google.crypto.tink.Mac;
import com.google.crypto.tink.internal.KeyTypeManager;
import com.google.crypto.tink.proto.AesCmacKey;
import com.google.crypto.tink.proto.AesCmacKeyFormat;
import com.google.crypto.tink.proto.AesCmacParams;
import com.google.crypto.tink.subtle.PrfAesCmac;
import com.google.crypto.tink.subtle.PrfMac;
import com.google.crypto.tink.subtle.Random;
import com.google.protobuf.ByteString;
import com.google.protobuf.ExtensionRegistryLite;
import java.security.GeneralSecurityException;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Test for AesCmacKeyManager. */
@RunWith(JUnit4.class)
public class AesCmacKeyManagerTest {
  private final AesCmacKeyManager manager = new AesCmacKeyManager();
  private final KeyTypeManager.KeyFactory<AesCmacKeyFormat, AesCmacKey> factory =
      manager.keyFactory();

  @Test
  public void validateKeyFormat_empty() throws Exception {
    assertThrows(
        GeneralSecurityException.class,
        () ->
            new AesCmacKeyManager()
                .keyFactory()
                .validateKeyFormat(AesCmacKeyFormat.getDefaultInstance()));
  }

  private static AesCmacKeyFormat makeAesCmacKeyFormat(int keySize, int tagSize) {
    return AesCmacKeyFormat.newBuilder()
        .setKeySize(keySize)
        .setParams(AesCmacParams.newBuilder().setTagSize(tagSize).build())
        .build();
  }

  @Test
  public void validateKeyFormat_valid() throws Exception {
    AesCmacKeyManager manager = new AesCmacKeyManager();
    manager.keyFactory().validateKeyFormat(makeAesCmacKeyFormat(32, 10));
    manager.keyFactory().validateKeyFormat(makeAesCmacKeyFormat(32, 11));
    manager.keyFactory().validateKeyFormat(makeAesCmacKeyFormat(32, 12));
    manager.keyFactory().validateKeyFormat(makeAesCmacKeyFormat(32, 13));
    manager.keyFactory().validateKeyFormat(makeAesCmacKeyFormat(32, 14));
    manager.keyFactory().validateKeyFormat(makeAesCmacKeyFormat(32, 15));
    manager.keyFactory().validateKeyFormat(makeAesCmacKeyFormat(32, 16));
  }

  @Test
  public void validateKeyFormat_notValid_throws() throws Exception {
    AesCmacKeyManager manager = new AesCmacKeyManager();
    assertThrows(
        GeneralSecurityException.class,
        () -> manager.keyFactory().validateKeyFormat(makeAesCmacKeyFormat(32, 9)));
    assertThrows(
        GeneralSecurityException.class,
        () -> manager.keyFactory().validateKeyFormat(makeAesCmacKeyFormat(32, 17)));
    assertThrows(
        GeneralSecurityException.class,
        () -> manager.keyFactory().validateKeyFormat(makeAesCmacKeyFormat(32, 32)));
    assertThrows(
        GeneralSecurityException.class,
        () -> manager.keyFactory().validateKeyFormat(makeAesCmacKeyFormat(16, 16)));
    assertThrows(
        GeneralSecurityException.class,
        () -> manager.keyFactory().validateKeyFormat(makeAesCmacKeyFormat(64, 16)));
  }

  @Test
  public void createKey_valid() throws Exception {
    AesCmacKeyManager manager = new AesCmacKeyManager();
    manager.validateKey(manager.keyFactory().createKey(makeAesCmacKeyFormat(32, 16)));
  }

  @Test
  public void createKey_checkValues() throws Exception {
    AesCmacKeyFormat keyFormat = makeAesCmacKeyFormat(32, 16);
    AesCmacKey key = new AesCmacKeyManager().keyFactory().createKey(keyFormat);
    assertThat(key.getKeyValue()).hasSize(keyFormat.getKeySize());
    assertThat(key.getParams().getTagSize()).isEqualTo(keyFormat.getParams().getTagSize());
  }

  @Test
  public void createKey_multipleTimes() throws Exception {
    AesCmacKeyManager manager = new AesCmacKeyManager();
    AesCmacKeyFormat keyFormat = makeAesCmacKeyFormat(32, 16);
    assertThat(manager.keyFactory().createKey(keyFormat).getKeyValue())
        .isNotEqualTo(manager.keyFactory().createKey(keyFormat).getKeyValue());
  }

  @Test
  public void validateKey_valid() throws Exception {
    AesCmacKeyManager manager = new AesCmacKeyManager();
    manager.validateKey(manager.keyFactory().createKey(makeAesCmacKeyFormat(32, 10)));
    manager.validateKey(manager.keyFactory().createKey(makeAesCmacKeyFormat(32, 11)));
    manager.validateKey(manager.keyFactory().createKey(makeAesCmacKeyFormat(32, 12)));
    manager.validateKey(manager.keyFactory().createKey(makeAesCmacKeyFormat(32, 13)));
    manager.validateKey(manager.keyFactory().createKey(makeAesCmacKeyFormat(32, 14)));
    manager.validateKey(manager.keyFactory().createKey(makeAesCmacKeyFormat(32, 15)));
    manager.validateKey(manager.keyFactory().createKey(makeAesCmacKeyFormat(32, 16)));
  }

  @Test
  public void validateKey_wrongVersion_throws() throws Exception {
    AesCmacKeyManager manager = new AesCmacKeyManager();
    AesCmacKey validKey = manager.keyFactory().createKey(makeAesCmacKeyFormat(32, 16));
    assertThrows(
        GeneralSecurityException.class,
        () -> manager.validateKey(AesCmacKey.newBuilder(validKey).setVersion(1).build()));
  }

  @Test
  public void validateKey_notValid_throws() throws Exception {
    AesCmacKeyManager manager = new AesCmacKeyManager();
    AesCmacKey validKey = manager.keyFactory().createKey(makeAesCmacKeyFormat(32, 16));
    assertThrows(
        GeneralSecurityException.class,
        () ->
            manager.validateKey(
                AesCmacKey.newBuilder(validKey)
                    .setKeyValue(ByteString.copyFrom(Random.randBytes(16)))
                    .build()));
    assertThrows(
        GeneralSecurityException.class,
        () ->
            manager.validateKey(
                AesCmacKey.newBuilder(validKey)
                    .setKeyValue(ByteString.copyFrom(Random.randBytes(64)))
                    .build()));
    assertThrows(
        GeneralSecurityException.class,
        () ->
            manager.validateKey(
                AesCmacKey.newBuilder(validKey)
                    .setParams(AesCmacParams.newBuilder(validKey.getParams()).setTagSize(0).build())
                    .build()));
    assertThrows(
        GeneralSecurityException.class,
        () ->
            manager.validateKey(
                AesCmacKey.newBuilder(validKey)
                    .setParams(AesCmacParams.newBuilder(validKey.getParams()).setTagSize(9).build())
                    .build()));
    assertThrows(
        GeneralSecurityException.class,
        () ->
            manager.validateKey(
                AesCmacKey.newBuilder(validKey)
                    .setParams(
                        AesCmacParams.newBuilder(validKey.getParams()).setTagSize(17).build())
                    .build()));
    assertThrows(
        GeneralSecurityException.class,
        () ->
            manager.validateKey(
                AesCmacKey.newBuilder(validKey)
                    .setParams(
                        AesCmacParams.newBuilder(validKey.getParams()).setTagSize(32).build())
                    .build()));
  }

  @Test
  public void getPrimitive_works() throws Exception {
    AesCmacKeyManager manager = new AesCmacKeyManager();
    AesCmacKey validKey = manager.keyFactory().createKey(makeAesCmacKeyFormat(32, 16));
    Mac managerMac = manager.getPrimitive(validKey, Mac.class);
    Mac directMac =
        new PrfMac(
            new PrfAesCmac(validKey.getKeyValue().toByteArray()),
            validKey.getParams().getTagSize());
    byte[] message = Random.randBytes(50);
    managerMac.verifyMac(directMac.computeMac(message), message);
  }

  @Test
  public void testAes256CmacTemplate() throws Exception {
    KeyTemplate template = AesCmacKeyManager.aes256CmacTemplate();
    assertThat(template.getTypeUrl()).isEqualTo(new AesCmacKeyManager().getKeyType());
    assertThat(template.getOutputPrefixType()).isEqualTo(KeyTemplate.OutputPrefixType.TINK);
    AesCmacKeyFormat format =
        AesCmacKeyFormat.parseFrom(template.getValue(), ExtensionRegistryLite.getEmptyRegistry());

    assertThat(format.getKeySize()).isEqualTo(32);
    assertThat(format.getParams().getTagSize()).isEqualTo(16);
  }

  @Test
  public void testRawAes256CmacTemplate() throws Exception {
    KeyTemplate template = AesCmacKeyManager.rawAes256CmacTemplate();
    assertThat(template.getTypeUrl()).isEqualTo(new AesCmacKeyManager().getKeyType());
    assertThat(template.getOutputPrefixType()).isEqualTo(KeyTemplate.OutputPrefixType.RAW);
    AesCmacKeyFormat format =
        AesCmacKeyFormat.parseFrom(template.getValue(), ExtensionRegistryLite.getEmptyRegistry());

    assertThat(format.getKeySize()).isEqualTo(32);
    assertThat(format.getParams().getTagSize()).isEqualTo(16);
  }

  @Test
  public void testKeyTemplateAndManagerCompatibility() throws Exception {
    AesCmacKeyManager manager = new AesCmacKeyManager();

    testKeyTemplateCompatible(manager, AesCmacKeyManager.aes256CmacTemplate());
    testKeyTemplateCompatible(manager, AesCmacKeyManager.rawAes256CmacTemplate());
  }

  @Test
  public void testKeyFormats() throws Exception {
    factory.validateKeyFormat(factory.keyFormats().get("AES256_CMAC").keyFormat);
    factory.validateKeyFormat(factory.keyFormats().get("AES256_CMAC_RAW").keyFormat);
  }
}
