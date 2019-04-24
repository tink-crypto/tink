// Copyright 2019 Google LLC
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
import static org.junit.Assert.fail;

import com.google.crypto.tink.proto.AesGcmKey;
import com.google.crypto.tink.proto.KeyData.KeyMaterialType;
import com.google.protobuf.ByteString;
import com.google.protobuf.InvalidProtocolBufferException;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Tests for InternalKeyManager. */
@RunWith(JUnit4.class)
public final class InternalKeyManagerTest {
  private static final ByteString TEST_BYTESTRING = ByteString.copyFromUtf8("Some text");

  private static class TestInternalKeyManager extends InternalKeyManager<AesGcmKey> {
    public TestInternalKeyManager(PrimitiveFactory<?, AesGcmKey>... factories) {
      super(AesGcmKey.class, factories);
    }

    @Override
    public String getKeyType() {
      return "KeyTypeUrl";
    }

    @Override
    public int getVersion() {
      return 1;
    }

    @Override
    public KeyMaterialType keyMaterialType() {
      return KeyMaterialType.SYMMETRIC;
    }

    @Override
    public void validateKey(AesGcmKey keyProto) {}

    @Override
    public AesGcmKey parseKey(ByteString byteString) throws InvalidProtocolBufferException {
      return AesGcmKey.parseFrom(byteString);
    }
  }

  @Test
  public void getPrimitive_works() throws Exception {
    InternalKeyManager<AesGcmKey> keyManager =
        new TestInternalKeyManager(
            new TestInternalKeyManager.PrimitiveFactory<Primitive1, AesGcmKey>(Primitive1.class) {
              @Override
              public Primitive1 getPrimitive(AesGcmKey key) {
                return new Primitive1(key.getKeyValue());
              }
            },
            new TestInternalKeyManager.PrimitiveFactory<Primitive2, AesGcmKey>(Primitive2.class) {
              @Override
              public Primitive2 getPrimitive(AesGcmKey key) {
                return new Primitive2(key.getKeyValue().size());
              }
            });
    Primitive1 primitive1 =
        keyManager.getPrimitive(
            AesGcmKey.newBuilder().setKeyValue(TEST_BYTESTRING).build(), Primitive1.class);
    assertThat(primitive1.getKeyValue()).isEqualTo(TEST_BYTESTRING);
    Primitive2 primitive2 =
        keyManager.getPrimitive(
            AesGcmKey.newBuilder().setKeyValue(TEST_BYTESTRING).build(), Primitive2.class);
    assertThat(primitive2.getSize()).isEqualTo(TEST_BYTESTRING.size());
  }

  @Test
  public void supportedPrimitives_equalsGivenPrimitives() throws Exception {
    InternalKeyManager<AesGcmKey> keyManager =
        new TestInternalKeyManager(
            new TestInternalKeyManager.PrimitiveFactory<Primitive1, AesGcmKey>(Primitive1.class) {
              @Override
              public Primitive1 getPrimitive(AesGcmKey key) {
                return new Primitive1(key.getKeyValue());
              }
            },
            new TestInternalKeyManager.PrimitiveFactory<Primitive2, AesGcmKey>(Primitive2.class) {
              @Override
              public Primitive2 getPrimitive(AesGcmKey key) {
                return new Primitive2(key.getKeyValue().size());
              }
            });
    assertThat(keyManager.supportedPrimitives())
        .containsExactly(Primitive1.class, Primitive2.class);
  }

  @Test
  public void getPrimitive_throwsForUnknownPrimitives() throws Exception {
    InternalKeyManager<AesGcmKey> keyManager = new TestInternalKeyManager();
    try {
      keyManager.getPrimitive(AesGcmKey.getDefaultInstance(), Primitive1.class);
      fail();
    } catch (IllegalArgumentException e) {
      // expected
    }
  }

  @Test
  public void keyFactory_throwsUnsupported() throws Exception {
    InternalKeyManager<AesGcmKey> keyManager = new TestInternalKeyManager();
    try {
      keyManager.keyFactory();
      fail();
    } catch (UnsupportedOperationException e) {
      // expected
    }
  }

  @Test
  public void constructor_repeatedPrimitive_throwsIllegalArgument() throws Exception {
    try {
        new TestInternalKeyManager(
            new TestInternalKeyManager.PrimitiveFactory<Primitive1, AesGcmKey>(Primitive1.class) {
              @Override
              public Primitive1 getPrimitive(AesGcmKey key) {
                return new Primitive1(key.getKeyValue());
              }
            },
            new TestInternalKeyManager.PrimitiveFactory<Primitive1, AesGcmKey>(Primitive1.class) {
              @Override
              public Primitive1 getPrimitive(AesGcmKey key) {
                return new Primitive1(key.getKeyValue());
              }
            });
      fail();
    } catch (IllegalArgumentException e) {
      // expected
    }
  }

  private static final class Primitive1 {
    public Primitive1(ByteString keyValue) {
      this.keyValue = keyValue;
    }

    private final ByteString keyValue;

    public ByteString getKeyValue() {
      return keyValue;
    }
  }

  private static final class Primitive2 {
    public Primitive2(int size) {
      this.size = size;
    }

    private final int size;

    public int getSize() {
      return size;
    }
  }
}
