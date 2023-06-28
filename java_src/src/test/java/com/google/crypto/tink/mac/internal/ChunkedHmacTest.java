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
import com.google.crypto.tink.mac.internal.HmacTestUtil.HmacTestVector;
import com.google.crypto.tink.subtle.Random;
import com.google.crypto.tink.util.SecretBytes;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.security.Security;
import java.util.Arrays;
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

  @DataPoints("hmacTestVectors")
  public static final HmacTestVector[] HMAC_TEST_VECTORS = HmacTestUtil.HMAC_TEST_VECTORS;

  @DataPoints("prefixedKeyTypes")
  public static final HmacTestVector[] PREFIXED_KEY_TYPES = HmacTestUtil.PREFIXED_KEY_TYPES;

  @DataPoints("createVerificationFailsFast")
  public static final HmacTestVector[] CREATE_VERIFICATION_FAILS_FAST =
      HmacTestUtil.CREATE_VERIFICATION_FAILS_FAST;

  // The SHA224 parameters are omitted since they seem to be unavailable on Android.
  @DataPoints("parameters")
  public static final HmacParameters[] PARAMETERS = {
    HmacTestUtil.createHmacParameters(16, 10, Variant.NO_PREFIX, HashType.SHA1),
    HmacTestUtil.createHmacParameters(16, 10, Variant.NO_PREFIX, HashType.SHA256),
    HmacTestUtil.createHmacParameters(16, 10, Variant.NO_PREFIX, HashType.SHA384),
    HmacTestUtil.createHmacParameters(16, 10, Variant.NO_PREFIX, HashType.SHA512),
    HmacTestUtil.createHmacParameters(16, 10, Variant.TINK, HashType.SHA1),
    HmacTestUtil.createHmacParameters(16, 10, Variant.TINK, HashType.SHA256),
    HmacTestUtil.createHmacParameters(16, 10, Variant.TINK, HashType.SHA384),
    HmacTestUtil.createHmacParameters(16, 10, Variant.TINK, HashType.SHA512),
    HmacTestUtil.createHmacParameters(16, 10, Variant.CRUNCHY, HashType.SHA1),
    HmacTestUtil.createHmacParameters(16, 10, Variant.CRUNCHY, HashType.SHA256),
    HmacTestUtil.createHmacParameters(16, 10, Variant.CRUNCHY, HashType.SHA384),
    HmacTestUtil.createHmacParameters(16, 10, Variant.CRUNCHY, HashType.SHA512),
    HmacTestUtil.createHmacParameters(16, 10, Variant.LEGACY, HashType.SHA1),
    HmacTestUtil.createHmacParameters(16, 10, Variant.LEGACY, HashType.SHA256),
    HmacTestUtil.createHmacParameters(16, 10, Variant.LEGACY, HashType.SHA384),
    HmacTestUtil.createHmacParameters(16, 10, Variant.LEGACY, HashType.SHA512),
  };

  @Theory
  public void testComputationVerification_includeKeyPrefixWhenPresent(
      @FromDataPoints("prefixedKeyTypes") HmacTestVector t) throws Exception {
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
      @FromDataPoints("createVerificationFailsFast") HmacTestVector t) throws Exception {
    assumeTrue(!TinkFips.useOnlyFips() || TinkFipsUtil.fipsModuleAvailable());
    ChunkedMac mac = new ChunkedHmacImpl(t.key);
    assertThrows(GeneralSecurityException.class, () -> mac.createVerification(t.tag));
  }

  @Theory
  public void testComputationVerification_computeTagCorrectly(
      @FromDataPoints("hmacTestVectors") HmacTestVector t) throws Exception {
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
        GeneralSecurityException.class,
        () -> new ChunkedHmacImpl(HmacTestUtil.HMAC_TEST_VECTORS[0].key));
  }

  @Theory
  public void testTagTruncation_failsVerifyMac(@FromDataPoints("hmacTestVectors") HmacTestVector t)
      throws Exception {
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
                HmacTestUtil.createHmacParameters(16, 16, Variant.NO_PREFIX, HashType.SHA1))
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
  public void testBitFlipMessage_failsVerifyMac(@FromDataPoints("hmacTestVectors") HmacTestVector t)
      throws Exception {
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
            .setParameters(
                HmacTestUtil.createHmacParameters(16, 16, Variant.NO_PREFIX, HashType.SHA1))
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
  public void testBitFlipTag_failsVerifyMac(@FromDataPoints("hmacTestVectors") HmacTestVector t)
      throws Exception {
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
            .setParameters(
                HmacTestUtil.createHmacParameters(16, 16, Variant.NO_PREFIX, HashType.SHA1))
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
    HmacTestVector t = HmacTestUtil.HMAC_TEST_VECTORS[0];
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
  public void testRandomized(@FromDataPoints("hmacTestVectors") HmacTestVector t) throws Exception {
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
      @FromDataPoints("hmacTestVectors") HmacTestVector t) throws Exception {
    assumeTrue(!TinkFips.useOnlyFips() || TinkFipsUtil.fipsModuleAvailable());

    ChunkedMac mac = new ChunkedHmacImpl(t.key);
    byte[] mutableTag = Arrays.copyOf(t.tag, t.tag.length);
    ChunkedMacVerification macVerification = mac.createVerification(mutableTag);
    mutableTag[0] ^= (byte) 0x01;
    macVerification.update(ByteBuffer.wrap(t.message));

    macVerification.verifyMac();
  }
}
