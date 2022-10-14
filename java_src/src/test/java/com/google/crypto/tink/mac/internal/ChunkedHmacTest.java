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
import static org.junit.Assume.assumeTrue;

import com.google.crypto.tink.InsecureSecretKeyAccess;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.Mac;
import com.google.crypto.tink.config.TinkFips;
import com.google.crypto.tink.config.internal.TinkFipsUtil;
import com.google.crypto.tink.mac.ChunkedMac;
import com.google.crypto.tink.mac.ChunkedMacComputation;
import com.google.crypto.tink.mac.ChunkedMacVerification;
import com.google.crypto.tink.mac.HmacKey;
import com.google.crypto.tink.mac.HmacParameters;
import com.google.crypto.tink.mac.HmacParameters.HashType;
import com.google.crypto.tink.mac.HmacParameters.Variant;
import com.google.crypto.tink.mac.MacConfig;
import com.google.crypto.tink.subtle.Hex;
import com.google.crypto.tink.subtle.Random;
import com.google.crypto.tink.util.SecretBytes;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.security.Security;
import java.util.Arrays;
import javax.annotation.Nullable;
import org.conscrypt.Conscrypt;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.experimental.theories.DataPoints;
import org.junit.experimental.theories.FromDataPoints;
import org.junit.experimental.theories.Theories;
import org.junit.experimental.theories.Theory;
import org.junit.runner.RunWith;

@RunWith(Theories.class)
public class ChunkedHmacTest {
  @BeforeClass
  public static void setUp() throws Exception {
    MacConfig.register();

    // If Tink is built in FIPS-only mode, register Conscrypt for the tests.
    if (TinkFips.useOnlyFips()) {
      try {
        Conscrypt.checkAvailability();
        Security.addProvider(Conscrypt.newProvider());
      } catch (Throwable cause) {
        throw new IllegalStateException(
            "Cannot test HMAC in FIPS-mode without Conscrypt Provider", cause);
      }
    }
  }

  private static class ChunkedHmacTestVector {
    public final HmacKey key;
    public final byte[] message;
    public final byte[] tag;

    public ChunkedHmacTestVector(
        Variant variant,
        @Nullable Integer id,
        HashType hashType,
        String key,
        String message,
        int tagSizeBytes,
        String tag) {
      this.key = createHmacKey(key, tagSizeBytes, variant, id, hashType);
      this.message = Hex.decode(message);
      this.tag = Hex.decode(tag);
    }
  }

  private static HmacParameters createHmacParameters(
      int keySizeBytes, int fullTagSizeBytes, Variant variant, HashType hashType) {
    try {
      return HmacParameters.builder()
          .setKeySizeBytes(keySizeBytes)
          .setTagSizeBytes(fullTagSizeBytes)
          .setVariant(variant)
          .setHashType(hashType)
          .build();
    } catch (GeneralSecurityException e) {
      throw new IllegalArgumentException("Incorrect parameters creation arguments", e);
    }
  }

  private static HmacKey createHmacKey(
      String key,
      int tagSizeBytes,
      Variant variant,
      @Nullable Integer idRequirement,
      HashType hashType) {
    try {
      return HmacKey.builder()
          .setKeyBytes(SecretBytes.copyFrom(Hex.decode(key), InsecureSecretKeyAccess.get()))
          .setParameters(
              createHmacParameters(
                  Hex.decode(key).length,
                  tagSizeBytes,
                  variant,
                  hashType))
          .setIdRequirement(idRequirement)
          .build();
    } catch (GeneralSecurityException e) {
      throw new IllegalArgumentException("Incorrect key creation arguments", e);
    }
  }

  // Test data from http://csrc.nist.gov/groups/STM/cavp/message-authentication.html#testing
  // and https://tools.ietf.org/html/rfc4231.
  @DataPoints("hmacTestVectors")
  public static final ChunkedHmacTestVector[] HMAC_TEST_VECTORS = {
    new ChunkedHmacTestVector(
        Variant.NO_PREFIX,
        null,
        HashType.SHA1,
        "816aa4c3ee066310ac1e6666cf830c375355c3c8ba18cfe1f50a48c988b46272",
        "220248f5e6d7a49335b3f91374f18bb8b0ff5e8b9a5853f3cfb293855d78301d837a0a2eb9e4f056f06c08361"
            + "bd07180ee802651e69726c28910d2baef379606815dcbab01d0dc7acb0ba8e65a2928130da0522f2b2b3d05260"
            + "885cf1c64f14ca3145313c685b0274bf6a1cb38e4f99895c6a8cc72fbe0e52c01766fede78a1a",
        16,
        "17cb2e9e98b748b5ae0f7078ea5519e5"),
    new ChunkedHmacTestVector(
        Variant.NO_PREFIX,
        null,
        HashType.SHA256,
        "6f35628d65813435534b5d67fbdb54cb33403d04e843103e6399f806cb5df95febbdd61236f33245",
        "752cff52e4b90768558e5369e75d97c69643509a5e5904e0a386cbe4d0970ef73f918f675945a9aefe26daea27"
            + "587e8dc909dd56fd0468805f834039b345f855cfe19c44b55af241fff3ffcd8045cd5c288e6c4e284c3720570b"
            + "58e4d47b8feeedc52fd1401f698a209fccfa3b4c0d9a797b046a2759f82a54c41ccd7b5f592b",
        16,
        "05d1243e6465ed9620c9aec1c351a186"),
    new ChunkedHmacTestVector(
        Variant.NO_PREFIX,
        null,
        HashType.SHA384,
        "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
        "4869205468657265",
        48,
        "afd03944d84895626b0825f4ab46907f15f9dadbe4101ec682aa034c7cebc59cfaea9ea9076ede7f4af152e8b2fa9cb6"),
    new ChunkedHmacTestVector(
        Variant.NO_PREFIX,
        null,
        HashType.SHA512,
        "726374c4b8df517510db9159b730f93431e0cd468d4f3821eab0edb93abd0fba46ab4f1ef35d54fec3d85fa89e"
            + "f72ff3d35f22cf5ab69e205c10afcdf4aaf11338dbb12073474fddb556e60b8ee52f91163ba314303ee0c910e6"
            + "4e87fbf302214edbe3f2",
        "ac939659dc5f668c9969c0530422e3417a462c8b665e8db25a883a625f7aa59b89c5ad0ece5712ca17442d1798"
            + "c6dea25d82c5db260cb59c75ae650be56569c1bd2d612cc57e71315917f116bbfa65a0aeb8af7840ee83d3e710"
            + "1c52cf652d2773531b7a6bdd690b846a741816c860819270522a5b0cdfa1d736c501c583d916",
        32,
        "bd3d2df6f9d284b421a43e5f9cb94bc4ff88a88243f1f0133bad0fb1791f6569"),
  };

  @DataPoints("prefixedKeyTypes")
  public static final ChunkedHmacTestVector[] PREFIXED_KEY_TYPES = {
      new ChunkedHmacTestVector(
          Variant.LEGACY,
          1234,
          HashType.SHA1,
          "816aa4c3ee066310ac1e6666cf830c375355c3c8ba18cfe1f50a48c988b46272",
          "220248f5e6d7a49335b3f91374f18bb8b0ff5e8b9a5853f3cfb293855d78301d837a0a2eb9e4f056f06c08361"
              + "bd07180ee802651e69726c28910d2baef379606815dcbab01d0dc7acb0ba8e65a2928130da0522f2b2b3d05260"
              + "885cf1c64f14ca3145313c685b0274bf6a1cb38e4f99895c6a8cc72fbe0e52c01766fede78a1a",
          16,
          "00000004d20c2676610ded1bce1967ec654526ca7b"),
      new ChunkedHmacTestVector(
          Variant.TINK,
          1234,
          HashType.SHA256,
          "6f35628d65813435534b5d67fbdb54cb33403d04e843103e6399f806cb5df95febbdd61236f33245",
          "752cff52e4b90768558e5369e75d97c69643509a5e5904e0a386cbe4d0970ef73f918f675945a9aefe26daea27"
              + "587e8dc909dd56fd0468805f834039b345f855cfe19c44b55af241fff3ffcd8045cd5c288e6c4e284c3720570b"
              + "58e4d47b8feeedc52fd1401f698a209fccfa3b4c0d9a797b046a2759f82a54c41ccd7b5f592b",
          16,
          "01000004d205d1243e6465ed9620c9aec1c351a186"),
      new ChunkedHmacTestVector(
          Variant.CRUNCHY,
          1234,
          HashType.SHA384,
          "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
          "4869205468657265",
          48,
          "00000004d2afd03944d84895626b0825f4ab46907f15f9dadbe4101ec682aa034c7cebc59cfaea9ea9076ede7f4af152e8b2fa9cb6"),
      new ChunkedHmacTestVector(
          Variant.TINK,
          1234,
          HashType.SHA512,
          "726374c4b8df517510db9159b730f93431e0cd468d4f3821eab0edb93abd0fba46ab4f1ef35d54fec3d85fa89e"
              + "f72ff3d35f22cf5ab69e205c10afcdf4aaf11338dbb12073474fddb556e60b8ee52f91163ba314303ee0c910e6"
              + "4e87fbf302214edbe3f2",
          "ac939659dc5f668c9969c0530422e3417a462c8b665e8db25a883a625f7aa59b89c5ad0ece5712ca17442d1798"
              + "c6dea25d82c5db260cb59c75ae650be56569c1bd2d612cc57e71315917f116bbfa65a0aeb8af7840ee83d3e710"
              + "1c52cf652d2773531b7a6bdd690b846a741816c860819270522a5b0cdfa1d736c501c583d916",
          32,
          "01000004d2bd3d2df6f9d284b421a43e5f9cb94bc4ff88a88243f1f0133bad0fb1791f6569"),
  };

  @DataPoints("createVerificationFailsFast")
  public static final ChunkedHmacTestVector[] CREATE_VERIFICATION_FAILS_FAST = {
      new ChunkedHmacTestVector( // Wrong prefix.
          Variant.LEGACY,
          1234,
          HashType.SHA1,
          "816aa4c3ee066310ac1e6666cf830c375355c3c8ba18cfe1f50a48c988b46272",
          "220248f5e6d7a49335b3f91374f18bb8b0ff5e8b9a5853f3cfb293855d78301d837a0a2eb9e4f056f06c08361"
              + "bd07180ee802651e69726c28910d2baef379606815dcbab01d0dc7acb0ba8e65a2928130da0522f2b2b3d05260"
              + "885cf1c64f14ca3145313c685b0274bf6a1cb38e4f99895c6a8cc72fbe0e52c01766fede78a1a",
          16,
          "17cb2e9e98b748b5ae0f7078ea5519e5"),
      new ChunkedHmacTestVector( // Wrong prefix.
          Variant.TINK,
          1234,
          HashType.SHA256,
          "6f35628d65813435534b5d67fbdb54cb33403d04e843103e6399f806cb5df95febbdd61236f33245",
          "752cff52e4b90768558e5369e75d97c69643509a5e5904e0a386cbe4d0970ef73f918f675945a9aefe26daea27"
              + "587e8dc909dd56fd0468805f834039b345f855cfe19c44b55af241fff3ffcd8045cd5c288e6c4e284c3720570b"
              + "58e4d47b8feeedc52fd1401f698a209fccfa3b4c0d9a797b046a2759f82a54c41ccd7b5f592b",
          16,
          "01075505d1243e6465ed9620c9aec1c351a186"),
      new ChunkedHmacTestVector( // Tag too short.
          Variant.CRUNCHY,
          1234,
          HashType.SHA384,
          "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
          "4869205468657265",
          16,
          "afd0"),
  };

  @Theory
  public void testComputationVerification_includeKeyPrefixWhenPresent(
      @FromDataPoints("prefixedKeyTypes") ChunkedHmacTestVector t) throws Exception {
    assumeTrue(!TinkFips.useOnlyFips() || TinkFipsUtil.fipsModuleAvailable());
    ChunkedHmacImpl chunkedHmacImpl = new ChunkedHmacImpl(t.key);

    try {
      ChunkedHmacComputation chunkedHmacComputation =
          (ChunkedHmacComputation) chunkedHmacImpl.createComputation();
      chunkedHmacComputation.update(ByteBuffer.wrap(t.message).asReadOnlyBuffer());
      assertThat(t.tag).isEqualTo(chunkedHmacComputation.computeMac());
    } catch (GeneralSecurityException e) {
      throw new AssertionError("Valid computation, should not throw exception", e);
    }

    try {
      ChunkedHmacVerification chunkedHmacVerification =
          (ChunkedHmacVerification) chunkedHmacImpl.createVerification(t.tag);
      chunkedHmacVerification.update(ByteBuffer.wrap(t.message));
      chunkedHmacVerification.verifyMac();
    } catch (GeneralSecurityException e) {
      throw new AssertionError("Valid tag, verification should not throw exception", e);
    }
  }

  @Theory
  public void testCreateVerificationFailsFast(
      @FromDataPoints("createVerificationFailsFast") ChunkedHmacTestVector t) throws Exception {
    assumeTrue(!TinkFips.useOnlyFips() || TinkFipsUtil.fipsModuleAvailable());
    ChunkedMac mac = new ChunkedHmacImpl(t.key);
    assertThrows(GeneralSecurityException.class, () -> mac.createVerification(t.tag));
  }

  @Theory
  public void testComputationVerification_computeTagCorrectly(
      @FromDataPoints("hmacTestVectors") ChunkedHmacTestVector t) throws Exception {
    assumeTrue(!TinkFips.useOnlyFips() || TinkFipsUtil.fipsModuleAvailable());
    ChunkedHmacImpl chunkedHmacImpl = new ChunkedHmacImpl(t.key);

    try {
      ChunkedHmacComputation chunkedHmacComputation =
          (ChunkedHmacComputation) chunkedHmacImpl.createComputation();
      chunkedHmacComputation.update(ByteBuffer.wrap(t.message).asReadOnlyBuffer());
      assertThat(t.tag).isEqualTo(chunkedHmacComputation.computeMac());
    } catch (GeneralSecurityException e) {
      throw new AssertionError("Valid computation, should not throw exception", e);
    }

    try {
      ChunkedHmacVerification chunkedHmacVerification =
          (ChunkedHmacVerification) chunkedHmacImpl.createVerification(t.tag);
      chunkedHmacVerification.update(ByteBuffer.wrap(t.message));
      chunkedHmacVerification.verifyMac();
    } catch (GeneralSecurityException e) {
      throw new AssertionError("Valid tag, verification should not throw exception", e);
    }
  }

  // The SHA224 parameters are omitted since they seem to be unavailable on Android.
  @DataPoints("parameters")
  public static final HmacParameters[] PARAMETERS = {
      createHmacParameters(16, 10, Variant.NO_PREFIX, HashType.SHA1),
      createHmacParameters(16, 10, Variant.NO_PREFIX, HashType.SHA256),
      createHmacParameters(16, 10, Variant.NO_PREFIX, HashType.SHA384),
      createHmacParameters(16, 10, Variant.NO_PREFIX, HashType.SHA512),

      createHmacParameters(16, 10, Variant.TINK, HashType.SHA1),
      createHmacParameters(16, 10, Variant.TINK, HashType.SHA256),
      createHmacParameters(16, 10, Variant.TINK, HashType.SHA384),
      createHmacParameters(16, 10, Variant.TINK, HashType.SHA512),

      createHmacParameters(16, 10, Variant.CRUNCHY, HashType.SHA1),
      createHmacParameters(16, 10, Variant.CRUNCHY, HashType.SHA256),
      createHmacParameters(16, 10, Variant.CRUNCHY, HashType.SHA384),
      createHmacParameters(16, 10, Variant.CRUNCHY, HashType.SHA512),

      createHmacParameters(16, 10, Variant.LEGACY, HashType.SHA1),
      createHmacParameters(16, 10, Variant.LEGACY, HashType.SHA256),
      createHmacParameters(16, 10, Variant.LEGACY, HashType.SHA384),
      createHmacParameters(16, 10, Variant.LEGACY, HashType.SHA512),
  };

  @Theory
  public void testCompatibility(@FromDataPoints("parameters") HmacParameters params)
      throws Exception {
    assumeTrue(!TinkFips.useOnlyFips() || TinkFipsUtil.fipsModuleAvailable());
    KeysetHandle keysetHandle =
        KeysetHandle
            .newBuilder()
            .addEntry(
                KeysetHandle
                    .generateEntryFromParameters(params)
                    .withFixedId(1234)
                    .makePrimary()
            ).build();
    Mac mac = keysetHandle.getPrimitive(Mac.class);
    HmacKey key = (HmacKey) keysetHandle.getAt(0).getKey();
    ChunkedMac chunkedMac = new ChunkedHmacImpl(key);
    ChunkedMacComputation chunkedMacComputation = chunkedMac.createComputation();

    byte[] testData = new byte[] {1, 2, 3, 4, 5, 6, 7, 8};
    chunkedMacComputation.update(ByteBuffer.wrap(testData));
    assertThat(mac.computeMac(testData)).isEqualTo(chunkedMacComputation.computeMac());
  }

  @Test
  public void testFailsIfFipsModuleNotAvailable() {
    assumeTrue(TinkFips.useOnlyFips() && !TinkFipsUtil.fipsModuleAvailable());
    assertThrows(
        GeneralSecurityException.class, () -> new ChunkedHmacImpl(HMAC_TEST_VECTORS[0].key));
  }

  @Theory
  public void testTagTruncation_failsVerifyMac(
      @FromDataPoints("hmacTestVectors") ChunkedHmacTestVector t) throws Exception {
    assumeTrue(!TinkFips.useOnlyFips() || TinkFipsUtil.fipsModuleAvailable());

    ChunkedMac mac = new ChunkedHmacImpl(t.key);

    for (int j = 1; j < t.tag.length; j++) {
      byte[] modifiedTag = Arrays.copyOf(t.tag, t.tag.length - j);
      ChunkedMacVerification macVerification = mac.createVerification(modifiedTag);
      macVerification.update(ByteBuffer.wrap(t.message));
      assertThrows(GeneralSecurityException.class, macVerification::verifyMac);
    }

    // Test with random keys.
    HmacKey key =
        HmacKey.builder()
            .setParameters(
                createHmacParameters(16, 16, Variant.NO_PREFIX, HashType.SHA1))
            .setKeyBytes(SecretBytes.randomBytes(16))
            .build();
    mac = new ChunkedHmacImpl(key);
    for (int j = 1; j < t.tag.length; j++) {
      byte[] modifiedTag = Arrays.copyOf(t.tag, t.tag.length - j);
      ChunkedMacVerification macVerification = mac.createVerification(modifiedTag);
      macVerification.update(ByteBuffer.wrap(t.message));
      assertThrows(GeneralSecurityException.class, macVerification::verifyMac);
    }
  }

  @Theory
  public void testBitFlipMessage_failsVerifyMac(
      @FromDataPoints("hmacTestVectors") ChunkedHmacTestVector t) throws Exception {
    assumeTrue(!TinkFips.useOnlyFips() || TinkFipsUtil.fipsModuleAvailable());

    ChunkedMac mac = new ChunkedHmacImpl(t.key);
    for (int b = 0; b < t.message.length; b++) {
      for (int bit = 0; bit < 8; bit++) {
        byte[] modifiedMessage = Arrays.copyOf(t.message, t.message.length);
        modifiedMessage[b] = (byte) (modifiedMessage[b] ^ (1 << bit));
        ChunkedMacVerification macVerification = mac.createVerification(t.tag);
        macVerification.update(ByteBuffer.wrap(modifiedMessage));
        assertThrows(GeneralSecurityException.class, macVerification::verifyMac);
      }
    }

    // Test with random keys.
    HmacKey key =
        HmacKey.builder()
            .setParameters(createHmacParameters(16, 16, Variant.NO_PREFIX, HashType.SHA1))
            .setKeyBytes(SecretBytes.randomBytes(16))
            .build();
    mac = new ChunkedHmacImpl(key);
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

  @Theory
  public void testBitFlipTag_failsVerifyMac(
      @FromDataPoints("hmacTestVectors") ChunkedHmacTestVector t) throws Exception {
    assumeTrue(!TinkFips.useOnlyFips() || TinkFipsUtil.fipsModuleAvailable());

    ChunkedMac mac = new ChunkedHmacImpl(t.key);
    for (int b = 0; b < t.tag.length; b++) {
      for (int bit = 0; bit < 8; bit++) {
        byte[] modifiedTag = Arrays.copyOf(t.tag, t.tag.length);
        modifiedTag[b] = (byte) (modifiedTag[b] ^ (1 << bit));
        ChunkedMacVerification macVerification = mac.createVerification(modifiedTag);
        macVerification.update(ByteBuffer.wrap(t.message));
        assertThrows(GeneralSecurityException.class, macVerification::verifyMac);
      }
    }

    // Test with random keys.
    HmacKey key =
        HmacKey.builder()
            .setParameters(createHmacParameters(16, 16, Variant.NO_PREFIX, HashType.SHA1))
            .setKeyBytes(SecretBytes.randomBytes(16))
            .build();
    mac = new ChunkedHmacImpl(key);
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

  @Test
  public void testUpdateAfterFinalize_throwsInComputationVerification() throws Exception {
    assumeTrue(!TinkFips.useOnlyFips() || TinkFipsUtil.fipsModuleAvailable());
    ChunkedHmacTestVector t = HMAC_TEST_VECTORS[0];
    ChunkedMac mac = new ChunkedHmacImpl(t.key);

    ChunkedMacComputation macComputation = mac.createComputation();
    macComputation.update(ByteBuffer.wrap(t.message));
    assertThat(t.tag).isEqualTo(macComputation.computeMac());
    assertThrows(
        IllegalStateException.class,
        () -> macComputation.update(ByteBuffer.wrap(t.message)));
    assertThrows(IllegalStateException.class, macComputation::computeMac);

    ChunkedMacVerification macVerification = mac.createVerification(t.tag);
    macVerification.update(ByteBuffer.wrap(t.message));
    macVerification.verifyMac();
    assertThrows(
        IllegalStateException.class,
        () -> macVerification.update(ByteBuffer.wrap(t.message)));
    assertThrows(IllegalStateException.class, macVerification::verifyMac);
  }

  @Theory
  public void testRandomized(@FromDataPoints("hmacTestVectors") ChunkedHmacTestVector t)
      throws Exception {
    ChunkedMac mac = new ChunkedHmacImpl(t.key);
    ChunkedMacComputation macComputation = mac.createComputation();

    int read = 0;
    StringBuilder debugReadSequence = new StringBuilder();
    debugReadSequence.append(
        "Hmac tag doesn't match; sequence of update() lengths that lead to the failure: ");

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

  @Theory
  public void testCreateVerification_copiesInputParameters(
      @FromDataPoints("hmacTestVectors") ChunkedHmacTestVector t) throws Exception {
    assumeTrue(!TinkFips.useOnlyFips() || TinkFipsUtil.fipsModuleAvailable());

    ChunkedMac mac = new ChunkedHmacImpl(t.key);
    byte[] mutableTag = Arrays.copyOf(t.tag, t.tag.length);
    ChunkedMacVerification macVerification = mac.createVerification(mutableTag);
    mutableTag[0] ^= (byte) 0x01;
    macVerification.update(ByteBuffer.wrap(t.message));

    macVerification.verifyMac();
  }
}
