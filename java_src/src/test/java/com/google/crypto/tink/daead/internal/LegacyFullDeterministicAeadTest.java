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

package com.google.crypto.tink.daead.internal;

import static com.google.common.truth.Truth.assertThat;
import static com.google.crypto.tink.internal.Util.isPrefix;

import com.google.crypto.tink.DeterministicAead;
import com.google.crypto.tink.InsecureSecretKeyAccess;
import com.google.crypto.tink.daead.internal.testing.LegacyAesSivTestKeyManager;
import com.google.crypto.tink.internal.LegacyProtoKey;
import com.google.crypto.tink.internal.ProtoKeySerialization;
import com.google.crypto.tink.proto.AesSivKey;
import com.google.crypto.tink.proto.KeyData.KeyMaterialType;
import com.google.crypto.tink.proto.OutputPrefixType;
import com.google.crypto.tink.subtle.Hex;
import com.google.crypto.tink.subtle.Random;
import com.google.crypto.tink.util.SecretBytes;
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
public class LegacyFullDeterministicAeadTest {
  private static final String TYPE_URL = "type.googleapis.com/custom.AesSivKey";

  @DataPoints("legacyFullDeterministicAeadTestVectors")
  public static final LegacyFullDeterministicAeadTestVector[] LEGACY_FULL_AEAD_TEST_VECTORS = {
    new LegacyFullDeterministicAeadTestVector(64, OutputPrefixType.RAW, null, ""),
    new LegacyFullDeterministicAeadTestVector(64, OutputPrefixType.TINK, 0x2a, "010000002a"),
    new LegacyFullDeterministicAeadTestVector(64, OutputPrefixType.CRUNCHY, 0x2a, "000000002a"),
    new LegacyFullDeterministicAeadTestVector(64, OutputPrefixType.LEGACY, 0x2a, "000000002a")
  };

  @BeforeClass
  public static void setUp() throws Exception {
    LegacyAesSivTestKeyManager.register();
  }

  @Theory
  public void create_works(
      @FromDataPoints("legacyFullDeterministicAeadTestVectors")
          LegacyFullDeterministicAeadTestVector t)
      throws Exception {
    DeterministicAead daead = LegacyFullDeterministicAead.create(t.key);

    assertThat(daead).isNotNull();
    assertThat(daead).isInstanceOf(LegacyFullDeterministicAead.class);
  }

  @Theory
  public void create_encrypt_correctOutputPrefix(
      @FromDataPoints("legacyFullDeterministicAeadTestVectors")
          LegacyFullDeterministicAeadTestVector t)
      throws Exception {
    DeterministicAead daead = LegacyFullDeterministicAead.create(t.key);

    byte[] plaintext = Random.randBytes(20);
    byte[] associatedData = Random.randBytes(20);

    byte[] ciphertext = daead.encryptDeterministically(plaintext, associatedData);

    assertThat(isPrefix(t.outputPrefix, ciphertext)).isTrue();
  }

  @Theory
  public void create_encrypt_decrypt_deterministically_works(
      @FromDataPoints("legacyFullDeterministicAeadTestVectors")
          LegacyFullDeterministicAeadTestVector t)
      throws Exception {
    DeterministicAead daead = LegacyFullDeterministicAead.create(t.key);

    byte[] plaintext = Random.randBytes(20);
    byte[] associatedData = Random.randBytes(20);

    byte[] ciphertext = daead.encryptDeterministically(plaintext, associatedData);
    byte[] ciphertext2 = daead.encryptDeterministically(plaintext, associatedData);
    byte[] decrypted = daead.decryptDeterministically(ciphertext, associatedData);
    byte[] decrypted2 = daead.decryptDeterministically(ciphertext2, associatedData);

    assertThat(ciphertext).isEqualTo(ciphertext2);
    assertThat(plaintext).isEqualTo(decrypted);
    assertThat(plaintext).isEqualTo(decrypted2);
  }

  /**
   * Represents a LegacyDterministicAead test utility which computes and stores the legacy proto key
   * and the output prefix.
   */
  private static final class LegacyFullDeterministicAeadTestVector {
    final LegacyProtoKey key;
    final byte[] outputPrefix;

    public LegacyFullDeterministicAeadTestVector(
        int keySizeBytes,
        OutputPrefixType outputPrefixType,
        @Nullable Integer idRequirement,
        String outputPrefix) {
      AesSivKey aesSivProtoKey =
          AesSivKey.newBuilder()
              .setVersion(0)
              .setKeyValue(
                  ByteString.copyFrom(
                      SecretBytes.randomBytes(keySizeBytes)
                          .toByteArray(InsecureSecretKeyAccess.get())))
              .build();

      try {
        this.key =
            new LegacyProtoKey(
                ProtoKeySerialization.create(
                    TYPE_URL,
                    aesSivProtoKey.toByteString(),
                    KeyMaterialType.SYMMETRIC,
                    outputPrefixType,
                    idRequirement),
                InsecureSecretKeyAccess.get());
      } catch (GeneralSecurityException e) {
        throw new RuntimeException(e);
      }
      this.outputPrefix = Hex.decode(outputPrefix);
    }
  }
}
