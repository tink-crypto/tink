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

package com.google.crypto.tink.keyderivation;

import static com.google.common.truth.Truth.assertThat;
import static java.nio.charset.StandardCharsets.UTF_8;
import static org.junit.Assert.assertThrows;

import com.google.crypto.tink.CleartextKeysetHandle;
import com.google.crypto.tink.InsecureSecretKeyAccess;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.PrimitiveSet;
import com.google.crypto.tink.TinkProtoKeysetFormat;
import com.google.crypto.tink.proto.KeyData;
import com.google.crypto.tink.proto.KeyStatusType;
import com.google.crypto.tink.proto.Keyset;
import com.google.crypto.tink.proto.OutputPrefixType;
import com.google.crypto.tink.subtle.Hex;
import com.google.errorprone.annotations.Immutable;
import java.security.GeneralSecurityException;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Tests for KeysetDeriverWrapper. */
@RunWith(JUnit4.class)
public class KeysetDeriverWrapperTest {
  @Immutable
  private static class DummyDeriver implements KeysetDeriver {
    private final String hexEncodedName;

    public DummyDeriver(byte[] name) {
      this.hexEncodedName = Hex.encode(name);
    }

    @Override
    public KeysetHandle deriveKeyset(byte[] salt) throws GeneralSecurityException {
      Keyset keyset =
          Keyset.newBuilder()
              .addKey(
                  Keyset.Key.newBuilder()
                      .setKeyData(
                          KeyData.newBuilder().setTypeUrl(hexEncodedName + ":" + Hex.encode(salt)))
                      .setStatus(KeyStatusType.UNKNOWN_STATUS)
                      .setKeyId(0)
                      .setOutputPrefixType(OutputPrefixType.UNKNOWN_PREFIX))
              .setPrimaryKeyId(0)
              .build();
      return TinkProtoKeysetFormat.parseKeyset(keyset.toByteArray(), InsecureSecretKeyAccess.get());
    }
  }

  private final KeysetDeriverWrapper wrapper = new KeysetDeriverWrapper();

  @Test
  public void test_wrapEmpty_throws() throws Exception {
    PrimitiveSet<KeysetDeriver> primitiveSet = PrimitiveSet.newBuilder(KeysetDeriver.class).build();

    assertThrows(GeneralSecurityException.class, () -> wrapper.wrap(primitiveSet));
  }

  @Test
  public void test_wrapNoPrimary_throws() throws Exception {
    PrimitiveSet<KeysetDeriver> primitiveSet =
        PrimitiveSet.newBuilder(KeysetDeriver.class)
            .addPrimitive(
                new DummyDeriver(new byte[0]),
                Keyset.Key.newBuilder()
                    .setKeyId(1234)
                    .setStatus(KeyStatusType.ENABLED)
                    .setOutputPrefixType(OutputPrefixType.TINK)
                    .build())
            .build();

    assertThrows(GeneralSecurityException.class, () -> wrapper.wrap(primitiveSet));
  }

  @Test
  public void test_wrapSingle_works() throws Exception {
    PrimitiveSet<KeysetDeriver> primitiveSet =
        PrimitiveSet.newBuilder(KeysetDeriver.class)
            .addPrimaryPrimitive(
                new DummyDeriver("wrap_single_key".getBytes(UTF_8)),
                Keyset.Key.newBuilder()
                    .setKeyId(1234)
                    .setStatus(KeyStatusType.ENABLED)
                    .setOutputPrefixType(OutputPrefixType.TINK)
                    .setKeyData(
                        KeyData.newBuilder()
                            .setTypeUrl(
                                "type.googleapis.com/google.crypto.tink.PrfBasedDeriverKey"))
                    .build())
            .build();

    KeysetDeriver wrapped = wrapper.wrap(primitiveSet);

    Keyset keyset = CleartextKeysetHandle.getKeyset(wrapped.deriveKeyset("salt".getBytes(UTF_8)));

    assertThat(keyset.getPrimaryKeyId()).isEqualTo(1234);
    assertThat(keyset.getKeyList()).hasSize(1);
    assertThat(keyset.getKey(0).getKeyData().getTypeUrl())
        .isEqualTo(
            Hex.encode("wrap_single_key".getBytes(UTF_8))
                + ":"
                + Hex.encode("salt".getBytes(UTF_8)));
    assertThat(keyset.getKey(0).getStatus()).isEqualTo(KeyStatusType.ENABLED);
    assertThat(keyset.getKey(0).getOutputPrefixType()).isEqualTo(OutputPrefixType.TINK);
  }

  @Test
  public void test_wrapMultiple_works() throws Exception {
    Keyset.Key key0 =
        Keyset.Key.newBuilder()
            .setKeyId(999999)
            .setStatus(KeyStatusType.ENABLED)
            .setOutputPrefixType(OutputPrefixType.RAW)
            .setKeyData(
                KeyData.newBuilder()
                    .setTypeUrl("type.googleapis.com/google.crypto.tink.PrfBasedDeriverKey"))
            .build();
    Keyset.Key key1 =
        Keyset.Key.newBuilder()
            .setKeyId(101010)
            .setStatus(KeyStatusType.ENABLED)
            .setOutputPrefixType(OutputPrefixType.LEGACY)
            .setKeyData(
                KeyData.newBuilder()
                    .setTypeUrl("type.googleapis.com/google.crypto.tink.PrfBasedDeriverKey"))
            .build();
    Keyset.Key key2 =
        Keyset.Key.newBuilder()
            .setKeyId(202020)
            .setStatus(KeyStatusType.ENABLED)
            .setOutputPrefixType(OutputPrefixType.TINK)
            .setKeyData(
                KeyData.newBuilder()
                    .setTypeUrl("type.googleapis.com/google.crypto.tink.PrfBasedDeriverKey"))
            .build();
    PrimitiveSet<KeysetDeriver> pset =
        PrimitiveSet.newBuilder(KeysetDeriver.class)
            .addPrimitive(new DummyDeriver("k0".getBytes(UTF_8)), key0)
            .addPrimaryPrimitive(new DummyDeriver("k1".getBytes(UTF_8)), key1)
            .addPrimitive(new DummyDeriver("k2".getBytes(UTF_8)), key2)
            .build();
    KeysetDeriver wrapped = wrapper.wrap(pset);

    Keyset keyset = CleartextKeysetHandle.getKeyset(wrapped.deriveKeyset("salt".getBytes(UTF_8)));
    assertThat(keyset.getPrimaryKeyId()).isEqualTo(101010);

    assertThat(keyset.getKey(0).getKeyData().getTypeUrl())
        .isEqualTo(Hex.encode("k0".getBytes(UTF_8)) + ":" + Hex.encode("salt".getBytes(UTF_8)));
    assertThat(keyset.getKey(0).getKeyId()).isEqualTo(999999);
    assertThat(keyset.getKey(0).getStatus()).isEqualTo(KeyStatusType.ENABLED);
    assertThat(keyset.getKey(0).getOutputPrefixType()).isEqualTo(OutputPrefixType.RAW);

    assertThat(keyset.getKey(1).getKeyData().getTypeUrl())
        .isEqualTo(Hex.encode("k1".getBytes(UTF_8)) + ":" + Hex.encode("salt".getBytes(UTF_8)));
    assertThat(keyset.getKey(1).getKeyId()).isEqualTo(101010);
    assertThat(keyset.getKey(1).getStatus()).isEqualTo(KeyStatusType.ENABLED);
    assertThat(keyset.getKey(1).getOutputPrefixType()).isEqualTo(OutputPrefixType.LEGACY);

    assertThat(keyset.getKey(2).getKeyData().getTypeUrl())
        .isEqualTo(Hex.encode("k2".getBytes(UTF_8)) + ":" + Hex.encode("salt".getBytes(UTF_8)));
    assertThat(keyset.getKey(2).getKeyId()).isEqualTo(202020);
    assertThat(keyset.getKey(2).getStatus()).isEqualTo(KeyStatusType.ENABLED);
    assertThat(keyset.getKey(2).getOutputPrefixType()).isEqualTo(OutputPrefixType.TINK);
  }
}
