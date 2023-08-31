// Copyright 2021 Google LLC
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
import com.google.crypto.tink.proto.Empty;
import com.google.crypto.tink.proto.KeyData.KeyMaterialType;
import com.google.protobuf.ByteString;
import com.google.protobuf.InvalidProtocolBufferException;
import java.security.GeneralSecurityException;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Tests for KeyTemplates * */
@RunWith(JUnit4.class)
public final class KeyTemplatesTest {

  private static class TestKeyTypeManager extends KeyTypeManager<Empty> {
    public TestKeyTypeManager() {
      super(Empty.class);
    }

    @Override
    public String getKeyType() {
      return "MY_TYPE_URL";
    }

    @Override
    public int getVersion() {
      return 0;
    }

    @Override
    public void validateKey(Empty keyProto) throws GeneralSecurityException {}

    @Override
    public KeyMaterialType keyMaterialType() {
      return KeyMaterialType.SYMMETRIC;
    }

    @Override
    public Empty parseKey(ByteString byteString) throws InvalidProtocolBufferException {
      return Empty.getDefaultInstance();
    }

    @Override
    public KeyFactory<Empty, Empty> keyFactory() {
      return new KeyFactory<Empty, Empty>(Empty.class) {
        @Override
        public Map<String, KeyTemplate> namedKeyTemplates(String typeUrl)
            throws GeneralSecurityException {
          Map<String, KeyTemplate> formats = new HashMap<>();
          formats.put(
              "TINK",
              KeyTemplate.createFrom(
                  new Parameters() {
                    @Override
                    public boolean hasIdRequirement() {
                      return true;
                    }
                  }));
          formats.put(
              "RAW",
              KeyTemplate.createFrom(
                  new Parameters() {
                    @Override
                    public boolean hasIdRequirement() {
                      return false;
                    }
                  }));
          return Collections.unmodifiableMap(formats);
        }

        @Override
        public void validateKeyFormat(Empty format) throws GeneralSecurityException {}

        @Override
        public Empty parseKeyFormat(ByteString byteString) throws InvalidProtocolBufferException {
          return Empty.getDefaultInstance();
        }

        @Override
        public Empty createKey(Empty format) throws GeneralSecurityException {
          return Empty.getDefaultInstance();
        }
      };
    }
  }

  @Test
  public void get() throws Exception {
    Registry.reset();

    Registry.registerKeyManager(new TestKeyTypeManager(), true);

    KeyTemplate template1 = KeyTemplates.get("TINK");
    assertThat(template1.toParameters().hasIdRequirement()).isEqualTo(true);

    KeyTemplate template2 = KeyTemplates.get("RAW");
    assertThat(template2.toParameters().hasIdRequirement()).isEqualTo(false);
  }

  @Test
  public void get_emptyRegistry_fails() {
    Registry.reset();

    assertThrows(GeneralSecurityException.class, () -> KeyTemplates.get("blah"));
  }

  @Test
  public void get_nonExistentName_fails() throws Exception {
    Registry.reset();
    Registry.registerKeyManager(new TestKeyTypeManager(), true);

    assertThrows(GeneralSecurityException.class, () -> KeyTemplates.get("blah"));
  }
}
