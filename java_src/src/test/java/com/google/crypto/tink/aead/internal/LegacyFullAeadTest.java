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

package com.google.crypto.tink.aead.internal;

import static com.google.common.truth.Truth.assertThat;
import static com.google.crypto.tink.internal.Util.isPrefix;
import static java.nio.charset.StandardCharsets.UTF_8;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;

import com.google.crypto.tink.Aead;
import com.google.crypto.tink.InsecureSecretKeyAccess;
import com.google.crypto.tink.internal.LegacyProtoKey;
import com.google.crypto.tink.internal.ProtoKeySerialization;
import com.google.crypto.tink.proto.AesCtrHmacAeadKey;
import com.google.crypto.tink.proto.AesCtrKey;
import com.google.crypto.tink.proto.AesCtrParams;
import com.google.crypto.tink.proto.HashType;
import com.google.crypto.tink.proto.HmacKey;
import com.google.crypto.tink.proto.HmacParams;
import com.google.crypto.tink.proto.KeyData.KeyMaterialType;
import com.google.crypto.tink.proto.OutputPrefixType;
import com.google.crypto.tink.subtle.AesGcmJce;
import com.google.crypto.tink.subtle.Hex;
import com.google.crypto.tink.util.Bytes;
import com.google.protobuf.ByteString;
import java.security.GeneralSecurityException;
import javax.annotation.Nullable;
import org.junit.BeforeClass;
import org.junit.experimental.theories.DataPoints;
import org.junit.experimental.theories.FromDataPoints;
import org.junit.experimental.theories.Theories;
import org.junit.experimental.theories.Theory;
import org.junit.runner.RunWith;

@RunWith(Theories.class)
public class LegacyFullAeadTest {
  private static final String TYPE_URL = "type.googleapis.com/custom.AesCtrHmacAeadKey";

  @DataPoints("legacyFullAeadTestVectors")
  public static final LegacyFullAeadTestVector[] LEGACY_FULL_AEAD_TEST_VECTORS = {
    new LegacyFullAeadTestVector(
        "abcdefabcdefabcdefabcdefabcdefab",
        "abcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcd",
        OutputPrefixType.RAW,
        null,
        "plaintext",
        "aad",
        "",
        "bf59daf09ae024df519ec07604a4f8fd"
            + "ac7dde7a733100932159a9f30cd54ce0"
            + "22b4169c653df2c4baed3eeb8ddbc2d1"
            + "e61252fe92808101f5"),
    new LegacyFullAeadTestVector(
        "abcdefabcdefabcdefabcdefabcdefab",
        "abcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcd",
        OutputPrefixType.TINK,
        0x2a,
        "plaintext",
        "aad",
        "010000002a",
        "010000002a"
            + "e3814bdffd61f8914e67c560f6f94bd4"
            + "4a57f7e3c245201692c822d9c685e131"
            + "94d0a9720a1250678491a45f99fe320a"
            + "be2faa5de9737c13d2"),
    new LegacyFullAeadTestVector(
        "abcdefabcdefabcdefabcdefabcdefab",
        "abcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcd",
        OutputPrefixType.CRUNCHY,
        0x2a,
        "plaintext",
        "aad",
        "000000002a",
        "000000002a"
            + "eb7b93b737f223817336573c5b161380"
            + "3e850f1c899427e8c1e00de057aa476d"
            + "de44ebcc2f02e84e975562cd15e2c2a8"
            + "06ec15c00dd4e28829"),
    new LegacyFullAeadTestVector(
        "abcdefabcdefabcdefabcdefabcdefab",
        "abcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcd",
        OutputPrefixType.LEGACY,
        0x2a,
        "plaintext",
        "aad",
        "000000002a",
        "000000002ab"
            + "ce14601adc6bf0a8f4e44136ddbe016c"
            + "d7db0f971515285a999916881ebc5280"
            + "247de0982561773686012297462b34f8"
            + "18daad65a2697c192")
  };

  @BeforeClass
  public static void setUp() throws Exception {
    LegacyAesCtrHmacTestKeyManager.register();
  }

  @Theory
  public void create_works(@FromDataPoints("legacyFullAeadTestVectors") LegacyFullAeadTestVector t)
      throws Exception {
    Aead aead = LegacyFullAead.create(t.key);

    assertThat(aead).isNotNull();
    assertThat(aead).isInstanceOf(LegacyFullAead.class);
  }

  @Theory
  public void create_encrypt_correctOutputPrefix(
      @FromDataPoints("legacyFullAeadTestVectors") LegacyFullAeadTestVector t) throws Exception {
    Aead aead = LegacyFullAead.create(t.key);

    byte[] ciphertext = aead.encrypt(t.plaintext, t.aad);

    assertTrue(isPrefix(t.outputPrefix, ciphertext));
  }

  @Theory
  public void create_decrypt_works(
      @FromDataPoints("legacyFullAeadTestVectors") LegacyFullAeadTestVector t) throws Exception {
    Aead aead = LegacyFullAead.create(t.key);

    assertThat(aead.decrypt(t.ciphertext, t.aad)).isEqualTo(t.plaintext);
  }

  private Aead rawAead() throws Exception {
    return new AesGcmJce(Hex.decode("abcdefabcdefabcdefabcdefabcdefab"));
  }

  @Theory
  public void createWithOutputPrefix_works() throws Exception {
    Aead rawAead = rawAead();
    byte[] outputPrefix = Hex.decode("01aabbccdd");

    Aead aead = LegacyFullAead.create(rawAead, Bytes.copyFrom(outputPrefix));

    byte[] plaintext = Hex.decode("11ff");
    byte[] associatedData = Hex.decode("22ee");

    byte[] ciphertext = aead.encrypt(plaintext, associatedData);
    assertTrue(isPrefix(outputPrefix, ciphertext));
    assertThat(aead.decrypt(ciphertext, associatedData)).isEqualTo(plaintext);
  }

  @Theory
  public void createWithInvalidOutputPrefix_fails() throws Exception {
    Aead rawAead = rawAead();
    byte[] tooShortOutputPrefix = Hex.decode("01aa");

    assertThrows(
        IllegalArgumentException.class,
        () -> LegacyFullAead.create(rawAead, Bytes.copyFrom(tooShortOutputPrefix)));
  }

  /** Represents a single LegacyAead test vector. */
  private static final class LegacyFullAeadTestVector {
    final LegacyProtoKey key;
    final byte[] plaintext;
    final byte[] aad;
    final byte[] outputPrefix;
    final byte[] ciphertext;

    public LegacyFullAeadTestVector(
        String aesCtrKey,
        String hmacKey,
        OutputPrefixType outputPrefixType,
        @Nullable Integer idRequirement,
        String plaintext,
        String aad,
        String outputPrefix,
        String ciphertext) {
      AesCtrKey aesCtrProtoKey =
          AesCtrKey.newBuilder()
              .setKeyValue(ByteString.copyFrom(Hex.decode(aesCtrKey)))
              .setParams(AesCtrParams.newBuilder().setIvSize(16).build())
              .build();
      HmacKey hmacProtoKey =
          HmacKey.newBuilder()
              .setParams(HmacParams.newBuilder().setHash(HashType.SHA256).setTagSize(32))
              .setKeyValue(ByteString.copyFrom(Hex.decode(hmacKey)))
              .build();
      AesCtrHmacAeadKey protoKey =
          AesCtrHmacAeadKey.newBuilder()
              .setAesCtrKey(aesCtrProtoKey)
              .setHmacKey(hmacProtoKey)
              .build();

      try {
        this.key =
            new LegacyProtoKey(
                ProtoKeySerialization.create(
                    TYPE_URL,
                    protoKey.toByteString(),
                    KeyMaterialType.SYMMETRIC,
                    outputPrefixType,
                    idRequirement),
                InsecureSecretKeyAccess.get());
      } catch (GeneralSecurityException e) {
        throw new RuntimeException(e);
      }
      this.plaintext = plaintext.getBytes(UTF_8);
      this.aad = aad.getBytes(UTF_8);
      this.outputPrefix = Hex.decode(outputPrefix);
      this.ciphertext = Hex.decode(ciphertext);
    }
  }
}
