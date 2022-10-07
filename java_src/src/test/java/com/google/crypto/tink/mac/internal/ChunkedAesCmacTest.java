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

package com.google.crypto.tink.mac.internal;

import static com.google.common.truth.Truth.assertThat;
import static org.junit.Assert.assertThrows;
import static org.junit.Assume.assumeFalse;
import static org.junit.Assume.assumeTrue;

import com.google.crypto.tink.InsecureSecretKeyAccess;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.Mac;
import com.google.crypto.tink.config.TinkFips;
import com.google.crypto.tink.mac.AesCmacKey;
import com.google.crypto.tink.mac.AesCmacParameters;
import com.google.crypto.tink.mac.AesCmacParameters.Variant;
import com.google.crypto.tink.mac.ChunkedMac;
import com.google.crypto.tink.mac.ChunkedMacComputation;
import com.google.crypto.tink.mac.ChunkedMacVerification;
import com.google.crypto.tink.mac.MacConfig;
import com.google.crypto.tink.subtle.Hex;
import com.google.crypto.tink.subtle.Random;
import com.google.crypto.tink.testing.WycheproofTestUtil;
import com.google.crypto.tink.util.SecretBytes;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.util.Arrays;
import javax.annotation.Nullable;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.experimental.theories.DataPoints;
import org.junit.experimental.theories.FromDataPoints;
import org.junit.experimental.theories.Theories;
import org.junit.experimental.theories.Theory;
import org.junit.runner.RunWith;

/* Unit tests for Streaming AesCmac computation. */
@RunWith(Theories.class)
public class ChunkedAesCmacTest {
  @BeforeClass
  public static void setUp() throws Exception {
    MacConfig.register();
  }

  private static class AesCmacTestVector {
    public final AesCmacKey key;
    public final byte[] message;
    public final byte[] tag;

    public AesCmacTestVector(AesCmacKey key, String message, String tag) {
      this.key = key;
      this.message = Hex.decode(message);
      this.tag = Hex.decode(tag);
    }
  }

  private static final AesCmacTestVector RFC_TEST_VECTOR_0 = new AesCmacTestVector(
      createAesCmacKey(
      "2b7e151628aed2a6abf7158809cf4f3c",
      createAesCmacParameters(16, 16, Variant.NO_PREFIX),
              null),
                  "",
                  "bb1d6929e95937287fa37d129b756746");
  private static final AesCmacTestVector RFC_TEST_VECTOR_1 = new AesCmacTestVector(
      createAesCmacKey(
      "2b7e151628aed2a6abf7158809cf4f3c",
      createAesCmacParameters(16, 16, Variant.NO_PREFIX),
              null),
                  "6bc1bee22e409f96e93d7e117393172a"
                  + "ae2d8a571e03ac9c9eb76fac45af8e51"
                  + "30c81c46a35ce411",
                  "dfa66747de9ae63030ca32611497c827");
  private static final AesCmacTestVector RFC_TEST_VECTOR_2 = new AesCmacTestVector(
      createAesCmacKey(
          "2b7e151628aed2a6abf7158809cf4f3c",
          createAesCmacParameters(16, 16, Variant.NO_PREFIX),
          null),
      "6bc1bee22e409f96e93d7e117393172a"
          + "ae2d8a571e03ac9c9eb76fac45af8e51"
          + "30c81c46a35ce411e5fbc1191a0a52ef"
          + "f69f2445df4f9b17ad2b417be66c3710",
      "51f0bebf7e3b9d92fc49741779363cfe");

  // Test data from https://tools.ietf.org/html/rfc4493#section-4.
  private static final AesCmacTestVector[] CMAC_TEST_VECTORS_FROM_RFC =
      new AesCmacTestVector[] {RFC_TEST_VECTOR_0, RFC_TEST_VECTOR_1, RFC_TEST_VECTOR_2};

  private static final AesCmacTestVector NOT_OVERFLOWING_INTERNAL_STATE = new AesCmacTestVector(
      createAesCmacKey(
          "00112233445566778899aabbccddeeff",
          createAesCmacParameters(16, 16, Variant.NO_PREFIX),
          null),
      "aaaaaa",
      "97268151a23fcd035a2dd0573d84e6ba");
  private static final AesCmacTestVector FILL_UP_EXACTLY_INTERNAL_STATE = new AesCmacTestVector(
      // fill up exactly the internal state once
      createAesCmacKey(
          "00112233445566778899aabbccddeeff",
          createAesCmacParameters(16, 16, Variant.NO_PREFIX),
          null),
      "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      "70e4648706483f8c5e8e2fab7b190c08");
  private static final AesCmacTestVector FILL_UP_EXACTLY_INTERNAL_STATE_TWICE =
      new AesCmacTestVector(
          createAesCmacKey(
              "00112233445566778899aabbccddeeff",
              createAesCmacParameters(16, 16, Variant.NO_PREFIX),
              null),
          "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
              + "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
          "219db2ebac5416dc2b0d8afcb666fb7a");
  private static final AesCmacTestVector OVERFLOW_INTERNAL_STATE_ONCE = new AesCmacTestVector(
      createAesCmacKey(
          "00112233445566778899aabbccddeeff",
          createAesCmacParameters(16, 16, Variant.NO_PREFIX),
          null),
      "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
          + "bbbbbb",
      "0336c9c4bf8f1bc219b017292af24358");
  private static final AesCmacTestVector OVERFLOW_INTERNAL_STATE_TWICE = new AesCmacTestVector(
      // overflow the internal state twice
      createAesCmacKey(
          "00112233445566778899aabbccddeeff",
          createAesCmacParameters(16, 16, Variant.NO_PREFIX),
          null),
      "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
          + "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
          + "bbbbbb",
      "611a1ededd3dfff548ed80b7fd10c0ba");
  private static final AesCmacTestVector SHORTER_TAG = new AesCmacTestVector(
      createAesCmacKey(
          "00112233445566778899aabbccddeeff",
          createAesCmacParameters(16, 15, Variant.NO_PREFIX),
          null),
      "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
          + "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
          + "bbbbbb",
      "611a1ededd3dfff548ed80b7fd10c0");
  private static final AesCmacTestVector TAG_WITH_KEY_PREFIX_TYPE_LEGACY = new AesCmacTestVector(
      createAesCmacKey(
          "00112233445566778899aabbccddeeff",
          createAesCmacParameters(16, 16, Variant.LEGACY),
          1877),
      "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
          + "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
          + "bbbbbb",
      "00000007554816512e20d15db74f1de942d86a2f7b");
  private static final AesCmacTestVector TAG_WITH_KEY_PREFIX_TYPE_TINK = new AesCmacTestVector(
      createAesCmacKey(
          "00112233445566778899aabbccddeeff",
          createAesCmacParameters(16, 16, Variant.TINK),
          1877),
      "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
          + "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
          + "bbbbbb",
      "0100000755611a1ededd3dfff548ed80b7fd10c0ba");
  private static final AesCmacTestVector LONG_KEY_TEST_VECTOR = new AesCmacTestVector(
      createAesCmacKey(
          "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",
          createAesCmacParameters(32, 16, Variant.NO_PREFIX),
          null),
      "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
          + "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
          + "bbbbbb",
      "139fce15a6f4a281ad22458d3d3cac26");
  private static final AesCmacTestVector[] CMAC_IMPLEMENTATION_DETAIL_TEST_VECTORS =
      new AesCmacTestVector[] {
        NOT_OVERFLOWING_INTERNAL_STATE,
        FILL_UP_EXACTLY_INTERNAL_STATE,
        FILL_UP_EXACTLY_INTERNAL_STATE_TWICE,
        OVERFLOW_INTERNAL_STATE_ONCE,
        OVERFLOW_INTERNAL_STATE_TWICE,
        SHORTER_TAG,
        TAG_WITH_KEY_PREFIX_TYPE_LEGACY,
        TAG_WITH_KEY_PREFIX_TYPE_TINK,
        LONG_KEY_TEST_VECTOR,
      };

  private static final AesCmacTestVector WRONG_PREFIX_TAG_LEGACY = new AesCmacTestVector(
      createAesCmacKey(
          "00112233445566778899aabbccddeeff",
          createAesCmacParameters(16, 16, Variant.LEGACY),
          1877),
      "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
          + "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
          + "bbbbbb",
      "0000611a1ededd3dfff548ed80b7fd10c0ba");
  private static final AesCmacTestVector WRONG_PREFIX_TAG_TINK = new AesCmacTestVector(
      createAesCmacKey(
          "00112233445566778899aabbccddeeff",
          createAesCmacParameters(16, 16, Variant.TINK),
          1877),
      "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
          + "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
          + "bbbbbb",
      "0100000745611a1ededd3dfff548ed80b7fd10c0ba");
  private static final AesCmacTestVector TAG_TOO_SHORT = new AesCmacTestVector(
      createAesCmacKey(
          "00112233445566778899aabbccddeeff",
          createAesCmacParameters(16, 16, Variant.TINK),
          1877),
      "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
          + "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
          + "bbbbbb",
      "c0ba");
  private static final AesCmacTestVector[] CMAC_VERIFICATION_FAIL_FAST_TEST_VECTORS =
      new AesCmacTestVector[] { WRONG_PREFIX_TAG_LEGACY, WRONG_PREFIX_TAG_TINK, TAG_TOO_SHORT};

  private static AesCmacKey createAesCmacKey(
      String keyMaterial, AesCmacParameters parameters, @Nullable Integer idRequirement) {
    try {
      return AesCmacKey.builder()
          .setAesKeyBytes(
              SecretBytes.copyFrom(Hex.decode(keyMaterial), InsecureSecretKeyAccess.get()))
          .setParameters(parameters)
          .setIdRequirement(idRequirement)
          .build();
    } catch (GeneralSecurityException ex) {
      throw new IllegalStateException(ex);
    }
  }

  private static AesCmacParameters createAesCmacParameters(
      int keySizeBytes, int tagSizeBytes, Variant variant) {
    try {
      return AesCmacParameters.builder()
          .setKeySizeBytes(keySizeBytes)
          .setVariant(variant)
          .setTagSizeBytes(tagSizeBytes)
          .build();
    } catch (GeneralSecurityException ex) {
      throw new IllegalStateException(ex);
    }
  }

  @DataPoints("parameters")
  public static final AesCmacParameters[] PARAMETERS = {
      createAesCmacParameters(32, 10, Variant.LEGACY),
      createAesCmacParameters(32, 11, Variant.LEGACY),
      createAesCmacParameters(32, 12, Variant.LEGACY),
      createAesCmacParameters(32, 13, Variant.LEGACY),
      createAesCmacParameters(32, 14, Variant.LEGACY),
      createAesCmacParameters(32, 15, Variant.LEGACY),
      createAesCmacParameters(32, 16, Variant.LEGACY),

      createAesCmacParameters(32, 10, Variant.TINK),
      createAesCmacParameters(32, 11, Variant.TINK),
      createAesCmacParameters(32, 12, Variant.TINK),
      createAesCmacParameters(32, 13, Variant.TINK),
      createAesCmacParameters(32, 14, Variant.TINK),
      createAesCmacParameters(32, 15, Variant.TINK),
      createAesCmacParameters(32, 16, Variant.TINK),

      createAesCmacParameters(32, 10, Variant.CRUNCHY),
      createAesCmacParameters(32, 11, Variant.CRUNCHY),
      createAesCmacParameters(32, 12, Variant.CRUNCHY),
      createAesCmacParameters(32, 13, Variant.CRUNCHY),
      createAesCmacParameters(32, 14, Variant.CRUNCHY),
      createAesCmacParameters(32, 15, Variant.CRUNCHY),
      createAesCmacParameters(32, 16, Variant.CRUNCHY),

      createAesCmacParameters(32, 10, Variant.NO_PREFIX),
      createAesCmacParameters(32, 11, Variant.NO_PREFIX),
      createAesCmacParameters(32, 12, Variant.NO_PREFIX),
      createAesCmacParameters(32, 13, Variant.NO_PREFIX),
      createAesCmacParameters(32, 14, Variant.NO_PREFIX),
      createAesCmacParameters(32, 15, Variant.NO_PREFIX),
      createAesCmacParameters(32, 16, Variant.NO_PREFIX),
  };

  @Theory
  public void testCompatibility(@FromDataPoints("parameters") AesCmacParameters parameters)
      throws Exception {
    KeysetHandle keysetHandle =
        KeysetHandle
            .newBuilder()
            .addEntry(
                KeysetHandle
                    .generateEntryFromParameters(parameters).withFixedId(1234).makePrimary())
            .build();
    Mac mac = keysetHandle.getPrimitive(Mac.class);
    AesCmacKey key = (AesCmacKey) keysetHandle.getAt(0).getKey();
    ChunkedMac chunkedMac = new ChunkedAesCmacImpl(key);
    ChunkedMacComputation chunkedMacComputation = chunkedMac.createComputation();

    byte[] testData = new byte[] {1, 2, 3, 4, 5, 6, 7, 8};
    chunkedMacComputation.update(ByteBuffer.wrap(testData));
    assertThat(mac.computeMac(testData)).isEqualTo(chunkedMacComputation.computeMac());
  }

  @Test
  public void testFipsCompatibility() {
    assumeTrue(TinkFips.useOnlyFips());

    // In FIPS-mode we expect that creating a ChunkedAesCmacImpl fails.
    assertThrows(
        GeneralSecurityException.class, () -> new ChunkedAesCmacImpl(RFC_TEST_VECTOR_0.key));
  }

  @Test
  public void testTagTruncation() throws Exception {
    assumeFalse(TinkFips.useOnlyFips());
    for (AesCmacTestVector t : CMAC_TEST_VECTORS_FROM_RFC) {
      ChunkedMac mac = new ChunkedAesCmacImpl(t.key);

      for (int j = 1; j < t.tag.length; j++) {
        byte[] modifiedTag = Arrays.copyOf(t.tag, t.tag.length - j);
        ChunkedMacVerification macVerification = mac.createVerification(modifiedTag);
        macVerification.update(ByteBuffer.wrap(t.message));
        assertThrows(GeneralSecurityException.class, macVerification::verifyMac);
      }
    }

    // Test with random keys.
    for (AesCmacTestVector t : CMAC_TEST_VECTORS_FROM_RFC) {
      AesCmacKey key =
          AesCmacKey.builder()
              .setParameters(
                  createAesCmacParameters(16, 16, Variant.NO_PREFIX))
              .setAesKeyBytes(SecretBytes.randomBytes(16))
              .build();
      ChunkedMac mac = new ChunkedAesCmacImpl(key);
      for (int j = 1; j < t.tag.length; j++) {
        byte[] modifiedTag = Arrays.copyOf(t.tag, t.tag.length - j);
        ChunkedMacVerification macVerification = mac.createVerification(modifiedTag);
        macVerification.update(ByteBuffer.wrap(t.message));
        assertThrows(GeneralSecurityException.class, macVerification::verifyMac);
      }
    }
  }

  @Test
  public void testBitFlipMessage() throws Exception {
    assumeFalse(TinkFips.useOnlyFips());
    for (AesCmacTestVector t : CMAC_TEST_VECTORS_FROM_RFC) {
      ChunkedMac mac = new ChunkedAesCmacImpl(t.key);
      for (int b = 0; b < t.message.length; b++) {
        for (int bit = 0; bit < 8; bit++) {
          byte[] modifiedMessage = Arrays.copyOf(t.message, t.message.length);
          modifiedMessage[b] = (byte) (modifiedMessage[b] ^ (1 << bit));
          ChunkedMacVerification macVerification = mac.createVerification(t.tag);
          macVerification.update(ByteBuffer.wrap(modifiedMessage));
          assertThrows(GeneralSecurityException.class, macVerification::verifyMac);
        }
      }
    }
    // Test with random keys.
    for (AesCmacTestVector t : CMAC_TEST_VECTORS_FROM_RFC) {
      AesCmacKey key =
          AesCmacKey.builder()
              .setParameters(createAesCmacParameters(16, 16, Variant.NO_PREFIX))
              .setAesKeyBytes(SecretBytes.randomBytes(16))
              .build();
      ChunkedMac mac = new ChunkedAesCmacImpl(key);
      for (int b = 0; b < t.message.length; b++) {
        for (int bit = 0; bit < 8; bit++) {
          byte[] modifiedMessage = Arrays.copyOf(t.message, t.message.length);
          modifiedMessage[b] = (byte) (modifiedMessage[b] ^ (1 << bit));
          ChunkedMacVerification macVerification = mac.createVerification(t.tag);
          macVerification.update(ByteBuffer.wrap(modifiedMessage));
          assertThrows(GeneralSecurityException.class, macVerification::verifyMac);
        }
      }
    }
  }

  @Test
  public void testBitFlipTag() throws Exception {
    assumeFalse(TinkFips.useOnlyFips());
    for (AesCmacTestVector t : CMAC_TEST_VECTORS_FROM_RFC) {
      ChunkedMac mac = new ChunkedAesCmacImpl(t.key);
      for (int b = 0; b < t.tag.length; b++) {
        for (int bit = 0; bit < 8; bit++) {
          byte[] modifiedTag = Arrays.copyOf(t.tag, t.tag.length);
          modifiedTag[b] = (byte) (modifiedTag[b] ^ (1 << bit));
          ChunkedMacVerification macVerification = mac.createVerification(modifiedTag);
          macVerification.update(ByteBuffer.wrap(t.message));
          assertThrows(GeneralSecurityException.class, macVerification::verifyMac);
        }
      }
    }
    // Test with random keys.
    for (AesCmacTestVector t : CMAC_TEST_VECTORS_FROM_RFC) {
      AesCmacKey key =
          AesCmacKey.builder()
              .setParameters(createAesCmacParameters(16, 16, Variant.NO_PREFIX))
              .setAesKeyBytes(SecretBytes.randomBytes(16))
              .build();
      ChunkedMac mac = new ChunkedAesCmacImpl(key);
      for (int b = 0; b < t.tag.length; b++) {
        for (int bit = 0; bit < 8; bit++) {
          byte[] modifiedTag = Arrays.copyOf(t.tag, t.tag.length);
          modifiedTag[b] = (byte) (modifiedTag[b] ^ (1 << bit));
          ChunkedMacVerification macVerification = mac.createVerification(modifiedTag);
          macVerification.update(ByteBuffer.wrap(t.message));
          assertThrows(GeneralSecurityException.class, macVerification::verifyMac);
        }
      }
    }
  }

  @Test
  public void testThrowExceptionUpdateAfterFinalize() throws Exception {
    assumeFalse(TinkFips.useOnlyFips());
    ChunkedMac mac = new ChunkedAesCmacImpl(RFC_TEST_VECTOR_0.key);

    ChunkedMacComputation macComputation = mac.createComputation();
    macComputation.update(ByteBuffer.wrap(RFC_TEST_VECTOR_0.message));
    assertThat(RFC_TEST_VECTOR_0.tag).isEqualTo(macComputation.computeMac());
    assertThrows(
        IllegalStateException.class,
        () -> macComputation.update(ByteBuffer.wrap(RFC_TEST_VECTOR_0.message)));
    assertThrows(IllegalStateException.class, macComputation::computeMac);

    ChunkedMacVerification macVerification = mac.createVerification(RFC_TEST_VECTOR_0.tag);
    macVerification.update(ByteBuffer.wrap(RFC_TEST_VECTOR_0.message));
    macVerification.verifyMac();
    assertThrows(
        IllegalStateException.class,
        () -> macVerification.update(ByteBuffer.wrap(RFC_TEST_VECTOR_0.message)));
    assertThrows(IllegalStateException.class, macVerification::verifyMac);
  }

  @Test
  public void testWycheproofVectors() throws Exception {
    JsonObject json =
        WycheproofTestUtil.readJson("../wycheproof/testvectors/aes_cmac_test.json");
    int errors = 0;
    JsonArray testGroups = json.getAsJsonArray("testGroups");
    for (int i = 0; i < testGroups.size(); i++) {
      JsonObject group = testGroups.get(i).getAsJsonObject();
      JsonArray tests = group.getAsJsonArray("tests");

      int tagSize = group.get("tagSize").getAsInt();
      int keySize = group.get("keySize").getAsInt();
      if (!Arrays.asList(16, 32).contains(keySize / 8)) {
        continue;
      }

      for (int j = 0; j < tests.size(); j++) {
        JsonObject testCase = tests.get(j).getAsJsonObject();
        String tcId =
            String.format(
                "testcase %d (%s)",
                testCase.get("tcId").getAsInt(), testCase.get("comment").getAsString());
        byte[] key = Hex.decode(testCase.get("key").getAsString());
        byte[] msg = Hex.decode(testCase.get("msg").getAsString());
        byte[] tag = Hex.decode(testCase.get("tag").getAsString());
        // Result is one of "valid", "invalid", "acceptable".
        // "valid" are test vectors with matching plaintext and tag.
        // "invalid" are test vectors with invalid parameters or invalid tag.
        // "acceptable" are test vectors with weak parameters or legacy formats, but there are no
        // "acceptable" tests cases for Aes Cmac.
        String result = testCase.get("result").getAsString();

        try {
          AesCmacParameters noPrefixParameters =
              AesCmacParameters.builder()
                  .setTagSizeBytes(tagSize / 8)
                  .setKeySizeBytes(keySize / 8).build();
          AesCmacKey aesCmacKey =
              AesCmacKey.builder()
                  .setAesKeyBytes(SecretBytes.copyFrom(key, InsecureSecretKeyAccess.get()))
                  .setParameters(noPrefixParameters).build();

          ChunkedMac mac = new ChunkedAesCmacImpl(aesCmacKey);

          ChunkedMacComputation macComputation = mac.createComputation();
          macComputation.update(ByteBuffer.wrap(msg));
          assertThat(tag).isEqualTo(macComputation.computeMac());

          ChunkedMacVerification macVerification = mac.createVerification(tag);
          macVerification.update(ByteBuffer.wrap(msg));
          macVerification.verifyMac();

          // If the test is "invalid" but no exception is thrown, it's an error.
          if (result.equals("invalid")) {
            System.out.printf("FAIL %s: invalid Wycheproof test did not fail%n", tcId);
            errors++;
          }
        } catch (GeneralSecurityException | AssertionError ex) {
          if (result.equals("valid")) {
            System.out.printf("FAIL %s: Wycheproof test failed, exception %s%n", tcId, ex);
            errors++;
          }
        }
      }
    }
    assertThat(errors).isEqualTo(0);
  }

  @Test
  public void testCreateVerificationFailsFast() throws Exception {
    assumeFalse(TinkFips.useOnlyFips());
    for (AesCmacTestVector t : CMAC_VERIFICATION_FAIL_FAST_TEST_VECTORS) {
      ChunkedMac mac = new ChunkedAesCmacImpl(t.key);
      assertThrows(GeneralSecurityException.class, () -> mac.createVerification(t.tag));
    }
  }

  /**
   * A cute little table to help verify that the tests below indeed cover the major (when not all)
   * code paths in our streaming AesCmac implementation:
   *
   * <p>-------------------------------------
   * | Inner state | Amount of new data |  # |
   * ----------------------------------------
   * | empty       | empty              |  0 |
   * | empty       | not overflowing    |  1 |
   * | empty       | overflowing        |  2 |
   * | empty       | a lot              |  3 |
   * ----------------------------------------
   * | some data   | empty              |  4 |
   * | some data   | not overflowing    |  5 |
   * | some data   | overflowing        |  6 |
   * | some data   | a lot              |  7 |
   * ----------------------------------------
   * | full        | empty              |  8 |
   * | full        | not overfl. (^)    |  9 |
   * | full        | overflowing        | 10 |
   * | full        | a lot              | 11 |
   * ----------------------------------------
   */

  /* ## 0, 2, 3 */
  @Test
  public void testMacTestVectors() throws Exception {
    assumeFalse(TinkFips.useOnlyFips());
    for (AesCmacTestVector t : CMAC_TEST_VECTORS_FROM_RFC) {
      ChunkedMac mac = new ChunkedAesCmacImpl(t.key);

      try {
        ChunkedMacComputation macComputation = mac.createComputation();
        macComputation.update(ByteBuffer.wrap(t.message));
        assertThat(t.tag).isEqualTo(macComputation.computeMac());
      } catch (GeneralSecurityException e) {
        throw new AssertionError("Valid computation, should not throw exception", e);
      }

      try {
        ChunkedMacVerification macVerification = mac.createVerification(t.tag);
        macVerification.update(ByteBuffer.wrap(t.message));
        macVerification.verifyMac();
      } catch (GeneralSecurityException e) {
        throw new AssertionError("Valid tag, verification should not throw exception", e);
      }
    }
  }

  /* ## 0, 2, 3 */
  @Test
  public void testMacTestVectorsReadOnlyBuffer() throws Exception {
    assumeFalse(TinkFips.useOnlyFips());
    for (AesCmacTestVector t : CMAC_TEST_VECTORS_FROM_RFC) {
      ChunkedMac mac = new ChunkedAesCmacImpl(t.key);

      try {
        ChunkedMacComputation macComputation = mac.createComputation();
        macComputation.update(ByteBuffer.wrap(t.message).asReadOnlyBuffer());
        assertThat(t.tag).isEqualTo(macComputation.computeMac());
      } catch (GeneralSecurityException e) {
        throw new AssertionError("Valid computation, should not throw exception", e);
      }

      try {
        ChunkedMacVerification macVerification = mac.createVerification(t.tag);
        macVerification.update(ByteBuffer.wrap(t.message).asReadOnlyBuffer());
        macVerification.verifyMac();
      } catch (GeneralSecurityException e) {
        throw new AssertionError("Valid tag, verification should not throw exception", e);
      }
    }
  }

  /* ## 1, 2, 3 */
  @Test
  public void testImplementationTestVectors() throws Exception {
    assumeFalse(TinkFips.useOnlyFips());
    for (AesCmacTestVector t : CMAC_IMPLEMENTATION_DETAIL_TEST_VECTORS) {
      ChunkedMac mac = new ChunkedAesCmacImpl(t.key);

      try {
        ChunkedMacComputation macComputation = mac.createComputation();
        macComputation.update(ByteBuffer.wrap(t.message));
        assertThat(t.tag).isEqualTo(macComputation.computeMac());
      } catch (GeneralSecurityException e) {
        throw new AssertionError("Valid computation, should not throw exception", e);
      }

      try {
        ChunkedMacVerification macVerification = mac.createVerification(t.tag);
        macVerification.update(ByteBuffer.wrap(t.message));
        macVerification.verifyMac();
      } catch (GeneralSecurityException e) {
        throw new AssertionError("Valid tag, verification should not throw exception", e);
      }
    }
  }

  /* # 0 */
  @Test
  public void testMultipleEmptyUpdates() throws Exception {
    assumeFalse(TinkFips.useOnlyFips());
    ChunkedMac mac = new ChunkedAesCmacImpl(RFC_TEST_VECTOR_0.key);

    ChunkedMacComputation macComputation = mac.createComputation();
    macComputation.update(ByteBuffer.wrap(RFC_TEST_VECTOR_0.message));
    macComputation.update(ByteBuffer.wrap(RFC_TEST_VECTOR_0.message));
    macComputation.update(ByteBuffer.wrap(RFC_TEST_VECTOR_0.message));
    macComputation.update(ByteBuffer.wrap(RFC_TEST_VECTOR_0.message));
    macComputation.update(ByteBuffer.wrap(RFC_TEST_VECTOR_0.message));
    assertThat(RFC_TEST_VECTOR_0.tag).isEqualTo(macComputation.computeMac());

    ChunkedMacVerification macVerification = mac.createVerification(RFC_TEST_VECTOR_0.tag);
    macVerification.update(ByteBuffer.wrap(RFC_TEST_VECTOR_0.message));
    macVerification.update(ByteBuffer.wrap(RFC_TEST_VECTOR_0.message));
    macVerification.update(ByteBuffer.wrap(RFC_TEST_VECTOR_0.message));
    macVerification.update(ByteBuffer.wrap(RFC_TEST_VECTOR_0.message));
    macVerification.update(ByteBuffer.wrap(RFC_TEST_VECTOR_0.message));
    macVerification.verifyMac();
  }

  /* ## 0, 1, 5, 6, 10  */
  @Test
  public void testSmallUpdates() throws Exception {
    assumeFalse(TinkFips.useOnlyFips());
    for (AesCmacTestVector t : CMAC_IMPLEMENTATION_DETAIL_TEST_VECTORS) {
      ChunkedMac mac = new ChunkedAesCmacImpl(t.key);

      ChunkedMacComputation macComputation = mac.createComputation();
      for (byte b : t.message) {
        byte[] bb = new byte[] {b};
        macComputation.update(ByteBuffer.wrap(bb));
      }
      assertThat(t.tag).isEqualTo(macComputation.computeMac());

      ChunkedMacVerification macVerification = mac.createVerification(t.tag);
      for (byte b : t.message) {
        byte[] bb = new byte[] {b};
        macVerification.update(ByteBuffer.wrap(bb));
      }
      macVerification.verifyMac();
    }
  }

  /* # 8, 9 */
  @Test
  public void testEmptyLastUpdateWithFullStash() throws Exception {
    assumeFalse(TinkFips.useOnlyFips());
    ChunkedMac mac = new ChunkedAesCmacImpl(FILL_UP_EXACTLY_INTERNAL_STATE.key);

    ChunkedMacComputation macComputation = mac.createComputation();
    macComputation.update(ByteBuffer.wrap(FILL_UP_EXACTLY_INTERNAL_STATE.message));
    macComputation.update(ByteBuffer.wrap(new byte[0]));
    assertThat(FILL_UP_EXACTLY_INTERNAL_STATE.tag).isEqualTo(macComputation.computeMac());

    ChunkedMacVerification macVerification =
        mac.createVerification(FILL_UP_EXACTLY_INTERNAL_STATE.tag);
    macVerification.update(ByteBuffer.wrap(FILL_UP_EXACTLY_INTERNAL_STATE.message));
    macVerification.update(ByteBuffer.wrap(new byte[0]));
    macVerification.verifyMac();
  }

  /* ## 1, 4, 5, 6, 7, 8, 9, 11 */
  @Test
  public void testMultipleUpdatesDifferentSizes() throws Exception {
    assumeFalse(TinkFips.useOnlyFips());
    ChunkedMac mac = new ChunkedAesCmacImpl(RFC_TEST_VECTOR_1.key);

    ChunkedMacComputation macComputation = mac.createComputation();
    macComputation.update(ByteBuffer.wrap(Arrays.copyOf(RFC_TEST_VECTOR_1.message, 14)));
    macComputation.update(ByteBuffer.wrap(new byte[0]));
    macComputation.update(ByteBuffer.wrap(Arrays.copyOfRange(RFC_TEST_VECTOR_1.message, 14, 36)));
    macComputation.update(ByteBuffer.wrap(Arrays.copyOfRange(RFC_TEST_VECTOR_1.message, 36, 40)));
    assertThat(RFC_TEST_VECTOR_1.tag).isEqualTo(macComputation.computeMac());

    ChunkedMacVerification macVerification = mac.createVerification(RFC_TEST_VECTOR_1.tag);
    macVerification.update(ByteBuffer.wrap(Arrays.copyOf(RFC_TEST_VECTOR_1.message, 32)));
    macVerification.update(ByteBuffer.wrap(new byte[0]));
    macVerification.update(ByteBuffer.wrap(Arrays.copyOfRange(RFC_TEST_VECTOR_1.message, 32, 40)));
    macVerification.verifyMac();

    macComputation = mac.createComputation();
    macComputation.update(ByteBuffer.wrap(Arrays.copyOf(RFC_TEST_VECTOR_2.message, 16)));
    macComputation.update(ByteBuffer.wrap(Arrays.copyOfRange(RFC_TEST_VECTOR_2.message, 16, 64)));
    assertThat(RFC_TEST_VECTOR_2.tag).isEqualTo(macComputation.computeMac());

    macVerification = mac.createVerification(RFC_TEST_VECTOR_2.tag);
    macVerification.update(ByteBuffer.wrap(Arrays.copyOf(RFC_TEST_VECTOR_2.message, 10)));
    macVerification.update(ByteBuffer.wrap(Arrays.copyOfRange(RFC_TEST_VECTOR_2.message, 10, 64)));
    macVerification.verifyMac();
  }

  /**
   * Finally, here comes a randomized test. In case, for some reason, the above tests do not catch
   * some bug, we'll have a chance to catch it here.
   */
  @Test
  public void testRandomizedDataChunking() throws Exception {
    assumeFalse(TinkFips.useOnlyFips());
    for (AesCmacTestVector t : CMAC_TEST_VECTORS_FROM_RFC) {
      testRandomized(t);
    }
    for (AesCmacTestVector t : CMAC_IMPLEMENTATION_DETAIL_TEST_VECTORS) {
      testRandomized(t);
    }

    // Only feed "valid" Wycheproof test cases into the randomized test.
    JsonObject json =
        WycheproofTestUtil.readJson("../wycheproof/testvectors/aes_cmac_test.json");
    JsonArray testGroups = json.getAsJsonArray("testGroups");
    for (int i = 0; i < testGroups.size(); i++) {
      JsonObject group = testGroups.get(i).getAsJsonObject();
      JsonArray tests = group.getAsJsonArray("tests");

      int tagSize = group.get("tagSize").getAsInt();
      int keySize = group.get("keySize").getAsInt();
      if (!Arrays.asList(16, 32).contains(keySize / 8)) {
        continue;
      }

      for (int j = 0; j < tests.size(); j++) {
        JsonObject testCase = tests.get(j).getAsJsonObject();
        if (!testCase.get("result").getAsString().equals("valid")) {
          continue;
        }

        String key = testCase.get("key").getAsString();
        String msg = testCase.get("msg").getAsString();
        String tag = testCase.get("tag").getAsString();

        testRandomized(new AesCmacTestVector(
            createAesCmacKey(
                key,
                createAesCmacParameters(keySize / 8, tagSize / 8, Variant.NO_PREFIX),
                null),
            msg,
            tag
        ));
      }
    }
  }

  private void testRandomized(AesCmacTestVector t) throws Exception {
    ChunkedMac mac = new ChunkedAesCmacImpl(t.key);
    ChunkedMacComputation macComputation = mac.createComputation();

    int read = 0;
    StringBuilder debugReadSequence = new StringBuilder();
    debugReadSequence.append(
        "AesCmac tag doesn't match; sequence of update() lengths that lead to the failure: ");

    for (int i = 0; i < 1000000 && read < t.message.length; i++) {
      // The upper bound is exclusive, hence the +1.
      int toRead = Random.randInt(t.message.length - read + 1);

      debugReadSequence.append(toRead);
      if (read + toRead < t.message.length) {
        debugReadSequence.append(", ");
      }

      macComputation.update(ByteBuffer.wrap(Arrays.copyOfRange(t.message, read, read + toRead)));
      read += toRead;
    }

    if (read < t.message.length) {
      debugReadSequence.append(t.message.length - read);
      macComputation.update(ByteBuffer.wrap(Arrays.copyOfRange(t.message, read, t.message.length)));
    }

    try {
      assertThat(t.tag).isEqualTo(macComputation.computeMac());
    } catch (AssertionError e) {
      throw new AssertionError(debugReadSequence.toString(), e);
    }
  }
}
