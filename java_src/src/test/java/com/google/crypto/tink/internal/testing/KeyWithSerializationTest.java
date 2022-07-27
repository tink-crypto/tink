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

package com.google.crypto.tink.internal.testing;

import static com.google.common.truth.Truth.assertThat;

import com.google.crypto.tink.Key;
import com.google.crypto.tink.Parameters;
import com.google.crypto.tink.internal.ProtoKeySerialization;
import com.google.crypto.tink.proto.KeyData.KeyMaterialType;
import com.google.crypto.tink.proto.OutputPrefixType;
import com.google.errorprone.annotations.Immutable;
import com.google.protobuf.ByteString;
import javax.annotation.Nullable;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

@RunWith(JUnit4.class)
public final class KeyWithSerializationTest {
  @Immutable
  private static final class TestKey extends Key {
    public TestKey() {}

    @Override
    public Parameters getParameters() {
      throw new UnsupportedOperationException("Not needed in test");
    }

    @Override
    @Nullable
    public Integer getIdRequirementOrNull() {
      throw new UnsupportedOperationException("Not needed in test");
    }

    @Override
    public boolean equalsKey(Key other) {
      throw new UnsupportedOperationException("Not needed in test");
    }
  }

  @Test
  public void testAll() throws Exception {
    Key key = new TestKey();
    ProtoKeySerialization serialization =
        ProtoKeySerialization.create(
            "typeUrl", ByteString.EMPTY, KeyMaterialType.SYMMETRIC, OutputPrefixType.RAW, null);
    KeyWithSerialization keyWithSerialization = new KeyWithSerialization(key, serialization);
    assertThat(keyWithSerialization.getKey()).isSameInstanceAs(key);
    assertThat(keyWithSerialization.getSerialization()).isSameInstanceAs(serialization);
  }
}
