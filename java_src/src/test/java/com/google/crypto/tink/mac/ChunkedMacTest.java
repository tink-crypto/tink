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

package com.google.crypto.tink.mac;

import static java.nio.charset.StandardCharsets.UTF_8;

import com.google.crypto.tink.Key;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.Mac;
import com.google.crypto.tink.mac.AesCmacParameters.Variant;
import com.google.crypto.tink.mac.HmacParameters.HashType;
import com.google.crypto.tink.util.SecretBytes;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import org.junit.BeforeClass;
import org.junit.experimental.theories.DataPoints;
import org.junit.experimental.theories.FromDataPoints;
import org.junit.experimental.theories.Theories;
import org.junit.experimental.theories.Theory;
import org.junit.runner.RunWith;

/**
 * These tests ensure interoperability between the new ChunkedMac implementations and the old Mac
 * implementations.
 */
@RunWith(Theories.class)
public class ChunkedMacTest {
  private static final int HMAC_KEY_SIZE = 20;
  private static final int HMAC_TAG_SIZE = 10;
  private static final int AES_CMAC_KEY_SIZE = 32;
  private static final int AES_CMAC_TAG_SIZE = 10;

  @DataPoints("keys")
  public static Key[] keys;

  @BeforeClass
  public static void setUp() throws Exception {
    MacConfig.register();
    AesCmacProtoSerialization.register();
    HmacProtoSerialization.register();
    ChunkedMacWrapper.register();
    createTestKeys();
  }

  private static void createTestKeys() {
    HmacParameters noPrefixHmacParameters =
        createDefaultHmacParameters(HmacParameters.Variant.NO_PREFIX);
    HmacParameters legacyHmacParameters =
        createDefaultHmacParameters(HmacParameters.Variant.LEGACY);
    HmacParameters crunchyHmacParameters =
        createDefaultHmacParameters(HmacParameters.Variant.CRUNCHY);
    HmacParameters tinkHmacParameters =
        createDefaultHmacParameters(HmacParameters.Variant.TINK);
    AesCmacParameters noPrefixAesCmacParameters =
        createDefaultAesCmacParameters(AesCmacParameters.Variant.NO_PREFIX);
    AesCmacParameters legacyAesCmacParameters =
        createDefaultAesCmacParameters(AesCmacParameters.Variant.LEGACY);
    AesCmacParameters crunchyAesCmacParameters =
        createDefaultAesCmacParameters(AesCmacParameters.Variant.CRUNCHY);
    AesCmacParameters tinkAesCmacParameters =
        createDefaultAesCmacParameters(AesCmacParameters.Variant.TINK);

    try {
      keys =
          new Key[] {
            HmacKey.builder()
                .setParameters(noPrefixHmacParameters)
                .setKeyBytes(SecretBytes.randomBytes(HMAC_KEY_SIZE))
                .setIdRequirement(null)
                .build(),
            AesCmacKey.builder()
                .setParameters(noPrefixAesCmacParameters)
                .setAesKeyBytes(SecretBytes.randomBytes(AES_CMAC_KEY_SIZE))
                .setIdRequirement(null)
                .build(),
            HmacKey.builder()
                .setParameters(tinkHmacParameters)
                .setKeyBytes(SecretBytes.randomBytes(HMAC_KEY_SIZE))
                .setIdRequirement(4)
                .build(),
            AesCmacKey.builder()
                .setParameters(tinkAesCmacParameters)
                .setAesKeyBytes(SecretBytes.randomBytes(AES_CMAC_KEY_SIZE))
                .setIdRequirement(5)
                .build(),
            HmacKey.builder()
                .setParameters(crunchyHmacParameters)
                .setKeyBytes(SecretBytes.randomBytes(HMAC_KEY_SIZE))
                .setIdRequirement(6)
                .build(),
            AesCmacKey.builder()
                .setParameters(crunchyAesCmacParameters)
                .setAesKeyBytes(SecretBytes.randomBytes(AES_CMAC_KEY_SIZE))
                .setIdRequirement(7)
                .build(),
            HmacKey.builder()
                .setParameters(legacyHmacParameters)
                .setKeyBytes(SecretBytes.randomBytes(HMAC_KEY_SIZE))
                .setIdRequirement(8)
                .build(),
            AesCmacKey.builder()
                .setParameters(legacyAesCmacParameters)
                .setAesKeyBytes(SecretBytes.randomBytes(AES_CMAC_KEY_SIZE))
                .setIdRequirement(9)
                .build(),
          };
    } catch (GeneralSecurityException e) {
      throw new IllegalStateException(e);
    }
  }

  private static AesCmacParameters createDefaultAesCmacParameters(Variant variant) {
    try {
      return AesCmacParameters.builder()
          .setKeySizeBytes(AES_CMAC_KEY_SIZE)
          .setTagSizeBytes(AES_CMAC_TAG_SIZE)
          .setVariant(variant)
          .build();
    } catch (GeneralSecurityException e) {
      throw new IllegalStateException(e);
    }
  }

  private static HmacParameters createDefaultHmacParameters(HmacParameters.Variant variant) {
    try {
      return HmacParameters.builder()
          .setKeySizeBytes(HMAC_KEY_SIZE)
          .setTagSizeBytes(HMAC_TAG_SIZE)
          .setVariant(variant)
          .setHashType(HashType.SHA256)
          .build();
    } catch (GeneralSecurityException e) {
      throw new IllegalArgumentException("Incorrect parameters creation arguments", e);
    }
  }

  @Theory
  public void computeWithMacVerifyWithChunkedMac_works(@FromDataPoints("keys") Key key)
      throws GeneralSecurityException {
    byte[] plaintext = "plaintext".getBytes(UTF_8);
    KeysetHandle.Builder.Entry entry = KeysetHandle.importKey(key);
    if (key.getIdRequirementOrNull() == null) {
      entry.withFixedId(1234);
    }
    KeysetHandle keysetHandle = KeysetHandle.newBuilder().addEntry(entry.makePrimary()).build();

    Mac mac = keysetHandle.getPrimitive(Mac.class);
    byte[] tag = mac.computeMac(plaintext);
    ChunkedMac chunkedMac = keysetHandle.getPrimitive(ChunkedMac.class);
    ChunkedMacVerification chunkedMacVerification = chunkedMac.createVerification(tag);
    chunkedMacVerification.update(ByteBuffer.wrap(plaintext));

    chunkedMacVerification.verifyMac();
  }

  @Theory
  public void computeWithChunkedMacVerifyWithMac_works(@FromDataPoints("keys") Key key)
      throws GeneralSecurityException {
    byte[] plaintext = "plaintext".getBytes(UTF_8);
    KeysetHandle.Builder.Entry entry = KeysetHandle.importKey(key);
    if (key.getIdRequirementOrNull() == null) {
      entry.withFixedId(1234);
    }
    KeysetHandle keysetHandle = KeysetHandle.newBuilder().addEntry(entry.makePrimary()).build();

    ChunkedMac chunkedMac = keysetHandle.getPrimitive(ChunkedMac.class);
    ChunkedMacComputation chunkedMacComputation = chunkedMac.createComputation();
    chunkedMacComputation.update(ByteBuffer.wrap(plaintext));
    byte[] tag = chunkedMacComputation.computeMac();
    Mac mac = keysetHandle.getPrimitive(Mac.class);

    mac.verifyMac(tag, plaintext);
  }
}
