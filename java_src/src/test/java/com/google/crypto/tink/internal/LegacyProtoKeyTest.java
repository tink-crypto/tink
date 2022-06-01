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

package com.google.crypto.tink.internal;

import static com.google.common.truth.Truth.assertThat;
import static org.junit.Assert.assertThrows;

import com.google.crypto.tink.InsecureSecretKeyAccess;
import com.google.crypto.tink.SecretKeyAccess;
import com.google.crypto.tink.proto.KeyData.KeyMaterialType;
import com.google.crypto.tink.proto.OutputPrefixType;
import com.google.protobuf.ByteString;
import java.security.GeneralSecurityException;
import java.util.Optional;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

@RunWith(JUnit4.class)
public final class LegacyProtoKeyTest {
  private static final Optional<SecretKeyAccess> ACCESS =
      Optional.of(InsecureSecretKeyAccess.get());

  @Test
  public void legacyProtoKeyCreate() throws Exception {
    ProtoKeySerialization serialization =
        ProtoKeySerialization.create(
            "myTypeUrl",
            ByteString.copyFrom(new byte[] {}),
            KeyMaterialType.SYMMETRIC,
            OutputPrefixType.RAW,
            Optional.empty());
    LegacyProtoKey key = new LegacyProtoKey(serialization, ACCESS);
    assertThat(key.getSerialization(ACCESS)).isSameInstanceAs(serialization);
  }

  @Test
  public void getIdRequirement() throws Exception {
    // RAW
    LegacyProtoKey key =
        new LegacyProtoKey(
            ProtoKeySerialization.create(
                "myTypeUrl",
                ByteString.copyFrom(new byte[] {}),
                KeyMaterialType.SYMMETRIC,
                OutputPrefixType.RAW,
                Optional.empty()),
            ACCESS);
    assertThat(key.getIdRequirement().isPresent()).isFalse();

    // TINK
    key =
        new LegacyProtoKey(
            ProtoKeySerialization.create(
                "myTypeUrl",
                ByteString.copyFrom(new byte[] {}),
                KeyMaterialType.SYMMETRIC,
                OutputPrefixType.TINK,
                Optional.of(123)),
            ACCESS);
    assertThat(key.getIdRequirement().get()).isEqualTo(123);

    // CRUNCHY
    key =
        new LegacyProtoKey(
            ProtoKeySerialization.create(
                "myTypeUrl",
                ByteString.copyFrom(new byte[] {}),
                KeyMaterialType.SYMMETRIC,
                OutputPrefixType.CRUNCHY,
                Optional.of(123)),
            ACCESS);
    assertThat(key.getIdRequirement().get()).isEqualTo(123);

    // LEGACY
    key =
        new LegacyProtoKey(
            ProtoKeySerialization.create(
                "myTypeUrl",
                ByteString.EMPTY,
                KeyMaterialType.SYMMETRIC,
                OutputPrefixType.LEGACY,
                Optional.of(123)),
            ACCESS);
    assertThat(key.getIdRequirement().get()).isEqualTo(123);
  }

  @Test
  public void constructorAccessCheck_symmetric_throws() throws Exception {
    ProtoKeySerialization serialization =
        ProtoKeySerialization.create(
            "myTypeUrl",
            ByteString.EMPTY,
            KeyMaterialType.SYMMETRIC,
            OutputPrefixType.RAW,
            Optional.empty());
    assertThrows(
        GeneralSecurityException.class, () -> new LegacyProtoKey(serialization, Optional.empty()));
    LegacyProtoKey key = new LegacyProtoKey(serialization, ACCESS);
    assertThrows(GeneralSecurityException.class, () -> key.getSerialization(Optional.empty()));
  }

  @Test
  public void constructorAccessCheck_asymmetricPrivate_throws() throws Exception {
    ProtoKeySerialization serialization =
        ProtoKeySerialization.create(
            "myTypeUrl",
            ByteString.EMPTY,
            KeyMaterialType.ASYMMETRIC_PRIVATE,
            OutputPrefixType.RAW,
            Optional.empty());
    assertThrows(
        GeneralSecurityException.class, () -> new LegacyProtoKey(serialization, Optional.empty()));
    LegacyProtoKey key = new LegacyProtoKey(serialization, ACCESS);
    assertThrows(GeneralSecurityException.class, () -> key.getSerialization(Optional.empty()));
  }

  @Test
  @SuppressWarnings("CheckReturnValue")
  public void constructorAccessCheck_asymmetricPublic_works() throws Exception {
    ProtoKeySerialization serialization =
        ProtoKeySerialization.create(
            "myTypeUrl",
            ByteString.EMPTY,
            KeyMaterialType.ASYMMETRIC_PUBLIC,
            OutputPrefixType.RAW,
            Optional.empty());
    LegacyProtoKey key = new LegacyProtoKey(serialization, Optional.empty());
    key.getSerialization(Optional.empty());
  }

  @Test
  @SuppressWarnings("CheckReturnValue")
  public void constructorAccessCheck_remote_works() throws Exception {
    ProtoKeySerialization serialization =
        ProtoKeySerialization.create(
            "myTypeUrl",
            ByteString.EMPTY,
            KeyMaterialType.REMOTE,
            OutputPrefixType.RAW,
            Optional.empty());
    LegacyProtoKey key = new LegacyProtoKey(serialization, Optional.empty());
    key.getSerialization(Optional.empty());
  }

  @Test
  public void testEquals() throws Exception {
    LegacyProtoKey key =
        new LegacyProtoKey(
            ProtoKeySerialization.create(
                "myTypeUrl",
                ByteString.EMPTY,
                KeyMaterialType.SYMMETRIC,
                OutputPrefixType.RAW,
                Optional.empty()),
            ACCESS);
    assertThat(
            key.equalsKey(
                new LegacyProtoKey(
                    ProtoKeySerialization.create(
                        "myTypeUrl",
                        ByteString.EMPTY,
                        KeyMaterialType.SYMMETRIC,
                        OutputPrefixType.RAW,
                        Optional.empty()),
                    ACCESS)))
        .isTrue();

    // Different type url:
    assertThat(
            key.equalsKey(
                new LegacyProtoKey(
                    ProtoKeySerialization.create(
                        "myTypeUrl2",
                        ByteString.EMPTY,
                        KeyMaterialType.SYMMETRIC,
                        OutputPrefixType.RAW,
                        Optional.empty()),
                    ACCESS)))
        .isFalse();

    // Different value:
    assertThat(
            key.equalsKey(
                new LegacyProtoKey(
                    ProtoKeySerialization.create(
                        "myTypeUrl",
                        ByteString.copyFrom(new byte[] {1}),
                        KeyMaterialType.SYMMETRIC,
                        OutputPrefixType.RAW,
                        Optional.empty()),
                    ACCESS)))
        .isFalse();

    // Different KeyMaterialType:
    assertThat(
            key.equalsKey(
                new LegacyProtoKey(
                    ProtoKeySerialization.create(
                        "myTypeUrl",
                        ByteString.EMPTY,
                        KeyMaterialType.ASYMMETRIC_PRIVATE,
                        OutputPrefixType.RAW,
                        Optional.empty()),
                    ACCESS)))
        .isFalse();

    // Different OutputPrefixType:
    assertThat(
            key.equalsKey(
                new LegacyProtoKey(
                    ProtoKeySerialization.create(
                        "myTypeUrl",
                        ByteString.EMPTY,
                        KeyMaterialType.SYMMETRIC,
                        OutputPrefixType.TINK,
                        Optional.of(123)),
                    ACCESS)))
        .isFalse();
  }

  @Test
  public void testEquals_differentIdRequirement() throws Exception {
    LegacyProtoKey key123 =
        new LegacyProtoKey(
            ProtoKeySerialization.create(
                "myTypeUrl",
                ByteString.EMPTY,
                KeyMaterialType.SYMMETRIC,
                OutputPrefixType.TINK,
                Optional.of(123)),
            ACCESS);
    LegacyProtoKey key123b =
        new LegacyProtoKey(
            ProtoKeySerialization.create(
                "myTypeUrl",
                ByteString.EMPTY,
                KeyMaterialType.SYMMETRIC,
                OutputPrefixType.TINK,
                Optional.of(123)),
            ACCESS);
    LegacyProtoKey key124 =
        new LegacyProtoKey(
            ProtoKeySerialization.create(
                "myTypeUrl",
                ByteString.EMPTY,
                KeyMaterialType.SYMMETRIC,
                OutputPrefixType.TINK,
                Optional.of(124)),
            ACCESS);
    assertThat(key123.equalsKey(key123b)).isTrue();
    assertThat(key123.equalsKey(key124)).isFalse();
  }
}
