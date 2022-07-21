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

package com.google.crypto.tink.testing;

import static com.google.common.truth.Truth.assertThat;
import static org.junit.Assert.assertThrows;

import com.google.crypto.tink.KeyTemplate;
import com.google.crypto.tink.internal.KeyTypeManager;
import com.google.crypto.tink.proto.AesGcmKey;
import com.google.crypto.tink.proto.AesGcmKeyFormat;
import com.google.crypto.tink.proto.KeyData.KeyMaterialType;
import com.google.crypto.tink.subtle.Random;
import com.google.protobuf.ByteString;
import com.google.protobuf.ExtensionRegistryLite;
import com.google.protobuf.InvalidProtocolBufferException;
import java.security.GeneralSecurityException;
import org.junit.Test;
import org.junit.function.ThrowingRunnable;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Tests for KeyTypeManagerTestUtil */
@RunWith(JUnit4.class)
public final class KeyTypeManagerTestUtilTest {

  private static class TestKeyTypeManager extends KeyTypeManager<AesGcmKey> {
    private final String typeUrl;

    public TestKeyTypeManager(String typeUrl) {
      super(AesGcmKey.class);
      this.typeUrl = typeUrl;
    }

    @Override
    public String getKeyType() {
      return typeUrl;
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
    public void validateKey(AesGcmKey keyProto) throws GeneralSecurityException {
      // Throw by hand so we can verify the exception comes from here.
      if (keyProto.getKeyValue().size() != 16) {
        throw new GeneralSecurityException("validateKey(AesGcmKey) failed");
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
          // Throw by hand so we can verify the exception comes from here.
          if (format.getKeySize() != 16) {
            throw new GeneralSecurityException("validateKeyFormat(AesGcmKeyFormat) failed");
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
              .setVersion(getVersion())
              .build();
        }
      };
    }
  }

  private static KeyTemplate createKeyTemplate(int keySize, String keyType) {
    AesGcmKeyFormat format = AesGcmKeyFormat.newBuilder().setKeySize(keySize).build();
    return KeyTemplate.create(keyType, format.toByteArray(), KeyTemplate.OutputPrefixType.TINK);
  }

  @Test
  public void testKeyTemplateCompatible_works() throws Exception {
    String typeUrl = "some_type_url";
    TestKeyTypeManager manager = new TestKeyTypeManager(typeUrl);
    KeyTypeManagerTestUtil.testKeyTemplateCompatible(manager, createKeyTemplate(16, typeUrl));
  }

  @Test
  public void testKeyTemplateCompatible_wrongUrl_throws() throws Exception {
    String typeUrl = "some_type_url";
    TestKeyTypeManager manager = new TestKeyTypeManager(typeUrl);
    assertThrows(
        AssertionError.class,
        new ThrowingRunnable() {
          @Override
          public void run() throws Throwable {
            KeyTypeManagerTestUtil.testKeyTemplateCompatible(
                manager, createKeyTemplate(16, typeUrl + "wrong"));
          }
        });
  }

  @Test
  public void testKeyTemplateCompatible_wrongKeySize_throws() throws Exception {
    String typeUrl = "some_type_url";
    TestKeyTypeManager manager = new TestKeyTypeManager(typeUrl);
    assertThrows(
        GeneralSecurityException.class,
        new ThrowingRunnable() {
          @Override
          public void run() throws Throwable {
            KeyTypeManagerTestUtil.testKeyTemplateCompatible(
                manager, createKeyTemplate(17, typeUrl));
          }
        });
  }

  @Test
  public void testKeyTemplateCompatible_properResult() throws Exception {
    String typeUrl = "some_type_url";
    TestKeyTypeManager manager = new TestKeyTypeManager(typeUrl);
    AesGcmKey key =
        KeyTypeManagerTestUtil.testKeyTemplateCompatible(manager, createKeyTemplate(16, typeUrl));
    assertThat(key.getKeyValue()).hasSize(16);
  }
}
