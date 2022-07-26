// Copyright 2022 Google LLC
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

import static com.google.common.truth.Truth.assertThat;
import static org.junit.Assert.assertThrows;

import com.google.crypto.tink.internal.KeyTypeManager;
import com.google.crypto.tink.internal.LegacyProtoKey;
import com.google.crypto.tink.internal.PrimitiveFactory;
import com.google.crypto.tink.proto.AesGcmKey;
import com.google.crypto.tink.proto.AesGcmKeyFormat;
import com.google.crypto.tink.proto.KeyData.KeyMaterialType;
import com.google.crypto.tink.subtle.AesGcmJce;
import com.google.crypto.tink.subtle.Random;
import com.google.protobuf.ByteString;
import com.google.protobuf.ExtensionRegistryLite;
import com.google.protobuf.InvalidProtocolBufferException;
import java.security.GeneralSecurityException;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/**
 * Tests for KeysetHandle. These tests especially test the code paths which go through
 * LegacyProtoKey and LegacyProtoParameters.
 */
@RunWith(JUnit4.class)
public final class KeysetHandleLegacyProtoKeyTest {
  /**
   * We use our own AesGcmKeymanager (copy pasted and slightly shortened from the original, only
   * accepting 128 bit keys). This ensures that even in future refactorings, we will not have key
   * parsing/serialization functions registered for this key type.
   */
  private static final class TestAesGcmKeyManager extends KeyTypeManager<AesGcmKey> {
    TestAesGcmKeyManager() {
      super(
          AesGcmKey.class,
          new PrimitiveFactory<Aead, AesGcmKey>(Aead.class) {
            @Override
            public Aead getPrimitive(AesGcmKey key) throws GeneralSecurityException {
              return new AesGcmJce(key.getKeyValue().toByteArray());
            }
          });
    }

    @Override
    public String getKeyType() {
      return "type.googleapis.com/google.crypto.tink.AesGcmKey";
    }

    @Override
    public int getVersion() {
      return 0;
    }

    @Override
    public KeyMaterialType keyMaterialType() {
      return KeyMaterialType.SYMMETRIC;
    }

    @Override
    public void validateKey(AesGcmKey key) throws GeneralSecurityException {
      if (key.getKeyValue().size() != 16) {
        throw new GeneralSecurityException("Wrong key size");
      }
    }

    @Override
    public AesGcmKey parseKey(ByteString byteString) throws InvalidProtocolBufferException {
      return AesGcmKey.parseFrom(byteString, ExtensionRegistryLite.getEmptyRegistry());
    }

    @Override
    public KeyFactory<AesGcmKeyFormat, AesGcmKey> keyFactory() {
      return new KeyFactory<AesGcmKeyFormat, AesGcmKey>(AesGcmKeyFormat.class) {
        @Override
        public void validateKeyFormat(AesGcmKeyFormat format) throws GeneralSecurityException {
          if (format.getKeySize() != 16) {
            throw new GeneralSecurityException("Wrong key size");
          }
        }

        @Override
        public AesGcmKeyFormat parseKeyFormat(ByteString byteString)
            throws InvalidProtocolBufferException {
          return AesGcmKeyFormat.parseFrom(byteString, ExtensionRegistryLite.getEmptyRegistry());
        }

        @Override
        public AesGcmKey createKey(AesGcmKeyFormat format) throws GeneralSecurityException {
          return AesGcmKey.newBuilder()
              .setKeyValue(ByteString.copyFrom(Random.randBytes(format.getKeySize())))
              .setVersion(0)
              .build();
        }

        @Override
        public Map<String, KeyFactory.KeyFormat<AesGcmKeyFormat>> keyFormats()
            throws GeneralSecurityException {
          Map<String, KeyFactory.KeyFormat<AesGcmKeyFormat>> result = new HashMap<>();
          result.put("AES128_GCM_FOR_TEST", createKeyFormat(16, KeyTemplate.OutputPrefixType.TINK));
          result.put(
              "AES128_GCM_FOR_TEST_RAW", createKeyFormat(16, KeyTemplate.OutputPrefixType.RAW));
          return Collections.unmodifiableMap(result);
        }
      };
    }

    public static void register(boolean newKeyAllowed) throws GeneralSecurityException {
      Registry.registerKeyManager(new TestAesGcmKeyManager(), newKeyAllowed);
    }

    private static KeyFactory.KeyFormat<AesGcmKeyFormat> createKeyFormat(
        int keySize, KeyTemplate.OutputPrefixType prefixType) {
      AesGcmKeyFormat format = AesGcmKeyFormat.newBuilder().setKeySize(keySize).build();
      return new KeyFactory.KeyFormat<>(format, prefixType);
    }
  }

  @BeforeClass
  public static void registerKeyManager() throws GeneralSecurityException {
    TestAesGcmKeyManager.register(true);
  }

  @Test
  public void testBuilder_basic() throws Exception {
    KeysetHandle keysetHandle =
        KeysetHandle.newBuilder()
            .addEntry(
                KeysetHandle.generateEntryFromParametersName("AES128_GCM_FOR_TEST")
                    .withRandomId()
                    .makePrimary())
            .build();

    assertThat(keysetHandle.size()).isEqualTo(1);
    assertThat(keysetHandle.getAt(0).getKey()).isInstanceOf(LegacyProtoKey.class);
  }

  @Test
  public void testBuilder_multipleKeys() throws Exception {
    KeysetHandle keysetHandle =
        KeysetHandle.newBuilder()
            .addEntry(
                KeysetHandle.generateEntryFromParametersName("AES128_GCM_FOR_TEST")
                    .withRandomId()
                    .setStatus(KeyStatus.DISABLED))
            .addEntry(
                KeysetHandle.generateEntryFromParametersName("AES128_GCM_FOR_TEST")
                    .withRandomId()
                    .makePrimary())
            .addEntry(
                KeysetHandle.generateEntryFromParametersName("AES128_GCM_FOR_TEST").withRandomId())
            .build();
    assertThat(keysetHandle.size()).isEqualTo(3);
    KeysetHandle.Entry entry0 = keysetHandle.getAt(0);
    assertThat(keysetHandle.getAt(0).getKey()).isInstanceOf(LegacyProtoKey.class);
    assertThat(entry0.isPrimary()).isFalse();
    assertThat(entry0.getStatus()).isEqualTo(KeyStatus.DISABLED);

    KeysetHandle.Entry entry1 = keysetHandle.getAt(1);
    assertThat(entry1.isPrimary()).isTrue();
    assertThat(entry1.getStatus()).isEqualTo(KeyStatus.ENABLED);
    assertThat(keysetHandle.getAt(1).getKey()).isInstanceOf(LegacyProtoKey.class);

    KeysetHandle.Entry entry2 = keysetHandle.getAt(2);
    assertThat(entry2.isPrimary()).isFalse();
    assertThat(entry2.getStatus()).isEqualTo(KeyStatus.ENABLED);
    assertThat(keysetHandle.getAt(2).getKey()).isInstanceOf(LegacyProtoKey.class);
  }

  @Test
  public void testBuilder_isPrimary_works() throws Exception {
    KeysetHandle.Builder builder = KeysetHandle.newBuilder();
    builder.addEntry(
        KeysetHandle.generateEntryFromParametersName("AES128_GCM_FOR_TEST").withRandomId());
    assertThat(builder.getAt(0).isPrimary()).isFalse();
    builder.getAt(0).makePrimary();
    assertThat(builder.getAt(0).isPrimary()).isTrue();
  }

  Key createKeyWithoutIdRequirement() throws Exception {
    Key result =
        KeysetHandle.newBuilder()
            .addEntry(
                KeysetHandle.generateEntryFromParametersName("AES128_GCM_FOR_TEST_RAW")
                    .withRandomId()
                    .makePrimary())
            .build()
            .getAt(0)
            .getKey();
    assertThat(result).isInstanceOf(LegacyProtoKey.class);
    return result;
  }

  Key createKeyWithIdRequirement(int id) throws Exception {
    Key result =
        KeysetHandle.newBuilder()
            .addEntry(
                KeysetHandle.generateEntryFromParametersName("AES128_GCM_FOR_TEST")
                    .withFixedId(id)
                    .makePrimary())
            .build()
            .getAt(0)
            .getKey();
    assertThat(result).isInstanceOf(LegacyProtoKey.class);
    return result;
  }

  @Test
  public void testImportKey_withoutIdRequirement_withFixedId_works() throws Exception {
    Key key = createKeyWithoutIdRequirement();
    KeysetHandle handle =
        KeysetHandle.newBuilder()
            .addEntry(KeysetHandle.importKey(key).withFixedId(102).makePrimary())
            .build();
    assertThat(handle.size()).isEqualTo(1);
    assertThat(handle.getAt(0).getId()).isEqualTo(102);
    assertThat(handle.getAt(0).getKey().equalsKey(key)).isTrue();
  }

  @Test
  public void testImportKey_withoutIdRequirement_noIdAssigned_throws() throws Exception {
    Key key = createKeyWithoutIdRequirement();
    KeysetHandle.Builder builder =
        KeysetHandle.newBuilder().addEntry(KeysetHandle.importKey(key).makePrimary());
    assertThrows(GeneralSecurityException.class, builder::build);
  }

  @Test
  public void testImportKey_withoutIdRequirement_withRandomId_works() throws Exception {
    Key key = createKeyWithoutIdRequirement();
    KeysetHandle handle =
        KeysetHandle.newBuilder()
            .addEntry(KeysetHandle.importKey(key).withRandomId().makePrimary())
            .build();
    assertThat(handle.size()).isEqualTo(1);
    assertThat(handle.getAt(0).getKey().equalsKey(key)).isTrue();
  }

  @Test
  public void testImportKey_withIdRequirement_noId_works() throws Exception {
    Key key = createKeyWithIdRequirement(105);
    KeysetHandle handle =
        KeysetHandle.newBuilder().addEntry(KeysetHandle.importKey(key).makePrimary()).build();
    assertThat(handle.size()).isEqualTo(1);
    assertThat(handle.getAt(0).getId()).isEqualTo(105);
    assertThat(handle.getAt(0).getKey().equalsKey(key)).isTrue();
  }

  @Test
  public void testImportKey_withIdRequirement_randomId_throws() throws Exception {
    Key key = createKeyWithIdRequirement(105);
    KeysetHandle.Builder builder =
        KeysetHandle.newBuilder()
            .addEntry(KeysetHandle.importKey(key).withRandomId().makePrimary());
    assertThrows(GeneralSecurityException.class, builder::build);
  }

  @Test
  public void testImportKey_withIdRequirement_explicitlySetToCorrectId_works() throws Exception {
    Key key = createKeyWithIdRequirement(1029);
    KeysetHandle handle =
        KeysetHandle.newBuilder()
            .addEntry(KeysetHandle.importKey(key).withFixedId(1029).makePrimary())
            .build();
    assertThat(handle.size()).isEqualTo(1);
    assertThat(handle.getAt(0).getId()).isEqualTo(1029);
    assertThat(handle.getAt(0).getKey().equalsKey(key)).isTrue();
  }

  @Test
  public void testImportKey_withIdRequirement_explicitlySetToWrongId_throws() throws Exception {
    Key key = createKeyWithIdRequirement(105);
    KeysetHandle.Builder builder =
        KeysetHandle.newBuilder()
            .addEntry(KeysetHandle.importKey(key).withFixedId(106).makePrimary());
    assertThrows(GeneralSecurityException.class, builder::build);
  }
}
